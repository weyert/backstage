# @backstage/plugin-tech-insights-backend

## 0.1.6-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.10.4-next.0
  - @backstage/config@0.1.13-next.0
  - @backstage/plugin-tech-insights-node@0.1.3-next.0
  - @backstage/catalog-model@0.9.10-next.0
  - @backstage/catalog-client@0.5.5-next.0

## 0.1.5

### Patch Changes

- 19f0f93504: Catch errors from a fact retriever and log them.
- 10f26e8883: Modify queries to perform better by filtering on sub-queries as well
- a60eb0f0dd: adding new operation to run checks for multiple entities in one request
- Updated dependencies
  - @backstage/config@0.1.12
  - @backstage/backend-common@0.10.3
  - @backstage/plugin-tech-insights-common@0.2.1
  - @backstage/errors@0.2.0
  - @backstage/catalog-client@0.5.4
  - @backstage/catalog-model@0.9.9

## 0.1.4

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.10.0
  - @backstage/catalog-client@0.5.3
  - @backstage/plugin-tech-insights-node@0.1.2

## 0.1.3

### Patch Changes

- b055a6addc: Align on usage of `cross-fetch` vs `node-fetch` in frontend vs backend packages, and remove some unnecessary imports of either one of them
- b5bd60fddc: Removed unnecessary check for specific server error in `@backstage plugin-tech-insights-backend`.
- c6c8b8e53e: Minor fixes in Readme to make the examples more directly usable.
- Updated dependencies
  - @backstage/plugin-tech-insights-common@0.2.0
  - @backstage/backend-common@0.9.12
  - @backstage/plugin-tech-insights-node@0.1.1

## 0.1.2

### Patch Changes

- 2017de90da: Update README docs to use correct function/parameter names
- Updated dependencies
  - @backstage/errors@0.1.5
  - @backstage/backend-common@0.9.11

## 0.1.1

### Patch Changes

- 5c00e45045: Add catalog fact retrievers

  Add fact retrievers which generate facts related to the completeness
  of entity data in the catalog.

- Updated dependencies
  - @backstage/catalog-client@0.5.2
  - @backstage/catalog-model@0.9.7
  - @backstage/backend-common@0.9.10
