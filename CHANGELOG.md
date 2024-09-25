## 1.0.1 (2024-09-25)

### Feat

- **tests**: add tests run to CI
- **tests**: add models tests and e2e tests
- **tests**: add fixtures

### Fix

- **lint**: fix mypy typing

## 1.0.1rc2 (2024-08-14)

### Fix

- **org-invite**: fix organization invitte payload
- **cipher-collections**: fix method changing collections of a cipher

## 1.0.1rc1 (2024-08-12)

### Fix

- **sync-seat-null**: Seats value can be null

## 1.0.1rc0 (2024-07-25)

### Fix

- **lint**: import fix
- **lint**: remove unused import
- **bitwarden**: fix List model and refresh master_ke when refresh token
- **typing**: fix mypy tiping and checks
- **default-values**: remove mutable default values
- **camelcase-api-field**: Allow parsing of API result with camel-cased field follow vaultwarden 1.31 changes
- **typing**: remove 'Optional' typing
- **ci**: trigger CI only when targeting main brancha

## 1.0.0 (2024-02-01)

### Feat

- **pydantic**: Rework Bitwarden Client with pydantic classes + Usage

## 0.7.0 (2023-08-09)

### Features

- **opensource**: First version of the open sourced python lib for Vaultwarden