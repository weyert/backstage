/*
 * Copyright 2022 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Entity, stringifyEntityRef } from '@backstage/catalog-model';
import { NotAllowedError } from '@backstage/errors';
import { catalogEntityReadPermission } from '@backstage/plugin-catalog-common';
import {
  AuthorizeResult,
  PermissionAuthorizer,
} from '@backstage/plugin-permission-common';
import { ConditionTransformer } from '@backstage/plugin-permission-node';
import {
  EntitiesCatalog,
  EntitiesRequest,
  EntitiesResponse,
  EntityAncestryResponse,
  EntityFilter,
} from '../catalog/types';

export class AuthorizedEntitiesCatalog implements EntitiesCatalog {
  constructor(
    private readonly entitiesCatalog: EntitiesCatalog,
    private readonly permissionApi: PermissionAuthorizer,
    private readonly transformConditions: ConditionTransformer<EntityFilter>,
  ) {}

  async entities(request?: EntitiesRequest): Promise<EntitiesResponse> {
    const authorizeResponse = (
      await this.permissionApi.authorize(
        [{ permission: catalogEntityReadPermission }],
        { token: request?.authorizationToken },
      )
    )[0];

    if (authorizeResponse.result === AuthorizeResult.DENY) {
      return {
        entities: [],
        pageInfo: { hasNextPage: false },
      };
    }

    if (authorizeResponse.result === AuthorizeResult.CONDITIONAL) {
      const permissionFilter: EntityFilter = this.transformConditions(
        authorizeResponse.conditions,
      );
      return this.entitiesCatalog.entities({
        ...request,
        filter: request?.filter
          ? { allOf: [permissionFilter, request.filter] }
          : permissionFilter,
      });
    }

    return this.entitiesCatalog.entities(request);
  }

  removeEntityByUid(uid: string): Promise<void> {
    // TODO: Implement permissioning
    return this.entitiesCatalog.removeEntityByUid(uid);
  }

  async entityAncestry(
    entityRef: string,
    authorizationToken?: string,
  ): Promise<EntityAncestryResponse> {
    const rootEntityAuthorizeResponse = (
      await this.permissionApi.authorize(
        [{ permission: catalogEntityReadPermission, resourceRef: entityRef }],
        { token: authorizationToken },
      )
    )[0];
    if (rootEntityAuthorizeResponse.result === AuthorizeResult.DENY) {
      throw new NotAllowedError();
    }

    const ancestryResult = await this.entitiesCatalog.entityAncestry(entityRef);
    const authorizeResponse = await this.permissionApi.authorize(
      ancestryResult.items.map(item => ({
        permission: catalogEntityReadPermission,
        resourceRef: stringifyEntityRef(item.entity),
      })),
      { token: authorizationToken },
    );
    const unauthorizedAncestryItems = ancestryResult.items.filter(
      (_, index) => authorizeResponse[index].result === AuthorizeResult.DENY,
    );
    const rootUnauthorizedEntityRefs = unauthorizedAncestryItems.map(
      ancestryItem => stringifyEntityRef(ancestryItem.entity),
    );
    const allUnauthorizedEntityRefs = new Set(
      rootUnauthorizedEntityRefs.concat(
        rootUnauthorizedEntityRefs
          .map(rootEntityRef =>
            this.findUnauthorizedParents(
              rootEntityRef,
              ancestryResult.items,
              new Set(rootUnauthorizedEntityRefs),
            ),
          )
          .flat(),
      ),
    );
    return {
      rootEntityRef: ancestryResult.rootEntityRef,
      items: ancestryResult.items.filter(
        ancestryItem =>
          !allUnauthorizedEntityRefs.has(
            stringifyEntityRef(ancestryItem.entity),
          ),
      ),
    };
  }

  private findUnauthorizedParents(
    entityRef: string,
    allAncestryItems: { entity: Entity; parentEntityRefs: string[] }[],
    seenEntityRefs: Set<string>,
  ): string[] {
    const entity = allAncestryItems.find(
      ancestryItem => stringifyEntityRef(ancestryItem.entity) === entityRef,
    );
    if (!entity) return [];

    const newSeenEntityRefs = new Set(seenEntityRefs);
    entity.parentEntityRefs.forEach(parentRef =>
      newSeenEntityRefs.add(parentRef),
    );

    return entity.parentEntityRefs
      .map(parentRef =>
        seenEntityRefs.has(parentRef)
          ? []
          : this.findUnauthorizedParents(
              parentRef,
              allAncestryItems,
              newSeenEntityRefs,
            ),
      )
      .flat();
  }
}
