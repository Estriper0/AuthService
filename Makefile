mock_user_repo:
	mockgen -source=internal/repository/repository.go -destination=internal/repository/mocks/mocks.go -package=mocks

mock_cache_repo:
	mockgen -source=internal/cache/cache.go -destination=internal/cache/mocks/mocks.go -package=mocks