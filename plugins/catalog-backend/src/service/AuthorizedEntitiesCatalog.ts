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

import { Entity } from '@backstage/catalog-model';
import { NotFoundError } from '@backstage/errors';
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
import { basicEntityFilter } from './request/basicEntityFilter';

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
    permissionOptions?: { authorizationToken?: string },
  ): Promise<EntityAncestryResponse> {
    const authorizeResponse = (
      await this.permissionApi.authorize(
        [{ permission: catalogEntityReadPermission, resourceRef: entityRef }],
        { token: permissionOptions?.authorizationToken },
      )
    )[0];

    if (authorizeResponse.result === AuthorizeResult.DENY) {
      return {
        rootEntityRef: entityRef,
        items: [],
      };
    }

    if (authorizeResponse.result === AuthorizeResult.CONDITIONAL) {
      const permissionFilter: EntityFilter = this.transformConditions(
        authorizeResponse.conditions,
      );
      const isEntityAuthorized = async (entity: Entity) => {
        const uid = entity.metadata.uid;
        if (!uid) {
          throw new NotFoundError();
        }
        const { entities } = await this.entitiesCatalog.entities({
          filter: {
            allOf: [
              permissionFilter,
              basicEntityFilter({ 'metadata.uid': uid }),
            ],
          },
          authorizationToken: permissionOptions?.authorizationToken,
        });
        return entities.length > 0;
      };
      return this.entitiesCatalog.entityAncestry(entityRef, {
        isEntityAuthorized,
      });
    }

    return this.entitiesCatalog.entityAncestry(entityRef);
  }
}
