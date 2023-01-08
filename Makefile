test-cover:
	go test -v -coverprofile=jwtcover.out
	go tool cover -html=jwtcover.out && unlink jwtcover.out