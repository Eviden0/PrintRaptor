package fingerprints

/*
初始化加载指纹信息,并且进行分类
*/
func LoadRules(path string) (CommonRules []CompiledRule, SpecialRules []CompiledRule, err error) {
	totalRules, err := LoadRulesFromFile(path)
	if err != nil {
		return nil, nil, err
	}
	for _, rule := range totalRules {
		if rule.Path == "" || rule.Path == "/" {
			CommonRules = append(CommonRules, rule)
		} else {
			SpecialRules = append(SpecialRules, rule)
		}
	}
	return CommonRules, SpecialRules, nil
}
