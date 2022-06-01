package zdpgo_password

import "os"

/*
@Time : 2022/6/1 16:40
@Author : 张大鹏
@File : util.go
@Software: Goland2021.3.1
@Description:
*/

// Exists 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}
