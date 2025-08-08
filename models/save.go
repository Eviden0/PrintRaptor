package models

//保存的方式
/*
1. 正常csv
2. 数据库
3. webhook
*/
// 抽象的保存结果接口
type Saver interface {
	Save() error
}

type WebhookSave struct {
	Banner *Banner
}

func (w *WebhookSave) Save() error {
	// 实现 webhook 发送逻辑
	return nil
}

type Result struct {
	Banner   *Banner
	SaveType uint8
}

// 实例化工厂
func (r *Result) GetSaver() Saver {
	switch r.SaveType {
	case 1:
		return &CsvSave{Banner: r.Banner}
	case 2:
		return &DbSave{Banner: r.Banner}
	case 3:
		return &WebhookSave{Banner: r.Banner}
	default:
		return &CsvSave{Banner: r.Banner} // 默认策略
	}
}
func Close() {
	CloseCsvFile()
	CloseMongoClient()
}
