module github.com/datadatdat/ssh-remote-go

require (
	github.com/datadatdat/remote-sdk-go v0.2.4
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto v0.0.0-20191227163750-53104e6ec876
)

go 1.13

replace (
	github.com/datadatdat/remote-sdk-go v0.2.1 => ../remote-sdk-go
	github.com/datadatdat/remote-sdk-go v0.2.4 => ../remote-sdk-go
)
