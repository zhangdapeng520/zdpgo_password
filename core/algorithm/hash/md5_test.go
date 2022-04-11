package hash

import "testing"

func getMd5() *Md5 {
	return NewMd5("abc")
}

func TestMd5_Encrypt(t *testing.T) {
	m := getMd5()
	result, err := m.Encrypt([]byte("abc"))
	t.Log(string(result))
	if err != nil {
		t.Error(err)
	}
}

func TestMd5_EncryptString(t *testing.T) {
	m := getMd5()
	result, err := m.EncryptString("abc")
	t.Log(result)
	if err != nil {
		t.Error(err)
	}
}

// 测试不使用Key的md5加密
func TestMd5_EncryptNoKey(t *testing.T) {
	m := getMd5()

	data := "abc"

	// 加密
	result := m.EncryptNoKey([]byte(data))
	t.Log(result)

	// 校验
	flag := m.CheckNoKey(result, []byte(data))
	t.Log(flag)

	// 加密
	result = m.EncryptStringNoKey(data)
	t.Log(result)

	// 校验
	flag = m.CheckStringNoKey(result, data)
	t.Log(flag)
}
