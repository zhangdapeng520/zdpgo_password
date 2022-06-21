package zdpgo_password

/*
@Time : 2022/6/21 17:58
@Author : 张大鹏
@File : form.go
@Software: Goland2021.3.1
@Description:
*/

// HttpServerInfo HTTP服务信息
type HttpServerInfo struct {
	Host     string                 `json:"host"`
	Port     int                    `json:"port"`
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	Email    string                 `json:"email"`
	Role     int                    `json:"role"`
	IsSsl    bool                   `json:"is_ssl"`
	Data     map[string]interface{} `json:"data"`
}
