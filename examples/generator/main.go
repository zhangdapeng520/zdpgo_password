package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password/generator"
	"os"
)

/*
@Time : 2022/6/21 17:16
@Author : 张大鹏
@File : main.go
@Software: Goland2021.3.1
@Description: 测试生成密码
*/

var (
	length                     uint   = generator.DefaultConfig.Length
	characterSet               string = generator.DefaultConfig.CharacterSet
	includeSymbols             bool   = generator.DefaultConfig.IncludeSymbols
	includeNumbers             bool   = generator.DefaultConfig.IncludeNumbers
	includeLowercaseLetters    bool   = generator.DefaultConfig.IncludeLowercaseLetters
	includeUppercaseLetters    bool   = generator.DefaultConfig.IncludeSymbols
	excludeSimilarCharacters   bool   = generator.DefaultConfig.ExcludeSimilarCharacters
	excludeAmbiguousCharacters bool   = generator.DefaultConfig.ExcludeAmbiguousCharacters
	times                      uint   = 10
)

func main() {
	generate()
}

func generate() {
	config := generator.Config{
		Length:                     length,
		CharacterSet:               characterSet,
		IncludeSymbols:             includeSymbols,
		IncludeNumbers:             includeNumbers,
		IncludeLowercaseLetters:    includeLowercaseLetters,
		IncludeUppercaseLetters:    includeUppercaseLetters,
		ExcludeSimilarCharacters:   excludeSimilarCharacters,
		ExcludeAmbiguousCharacters: excludeAmbiguousCharacters,
	}
	g, err := generator.New(&config)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// 生成1个密码
	data, err := g.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Println("生成1个密码：", *data)

	// 生成10个密码
	pwds, err := g.GenerateMany(times)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	for _, pwd := range pwds {
		fmt.Println(pwd)
	}
}
