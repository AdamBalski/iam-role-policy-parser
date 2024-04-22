# AWS::IAM::RolePolicy parser
This project provides an easy way to check whether the Resource value of an role policy statement is a wildcard.

Works with AWS::IAM::RolePolicy versions "2012-10-17 and "2008-10-17".
#### Note: This is done as a part of a coding challenge for a job application of an undisclosed company

## Function type signature
The function as well as the type `IamRolePolicy` reside in the `iamrolepolicyparsing` package.
```go
func (p *IamRolePolicy) HasAStatementResourceAWildcard() bool
```
## Code example (excerpt from commandline.go)
```go
iamRolePolicy := iamrolepolicyparsing.IamRolePolicy{}
err = iamRolePolicy.UnmarshalJSON(json)
if err != nil {
    fmt.Println("Error parsing file:", err.Error())
    os.Exit(1)
}

println(iamRolePolicy.HasAStatementResourceAWildcard())
```

## You can use the method as is or compile the program and run it with a commandline argument that takes a file name
### Dependencies:
- Go 1.22
### To compile:
```bash
go build main
```
### To run:
```bash
./main json-filename
```
### There are example json files in the `./example-jsons` directory
### Example usage:
![showcase](./readme-imgs/showcase.png)

## Disclaimers
The level of detail in which the jsons are verified is limited and I have not verified the following structures:
* action_string
* sid_string
* principal_id_string
* condition_type_string
* condition_key_string
* condition_value_string
 
As per [the AWS::IAM::RolePolicy grammar documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html).
