package fingerprints

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"unicode"
)

// ============================================================================
// SECTION 1: YAML and Rule Structures
// ============================================================================

// RuleConfig 映射了 YAML 文件中的单条规则结构
type RuleConfig struct {
	Name       string `yaml:"name"`
	Path       string `yaml:"path"`
	Expression string `yaml:"expression"`
	Rank       int    `yaml:"rank"`
	Tag        string `yaml:"tag"`
	IsPost     bool   `yaml:"isPost"`
}

// CompiledRule 存储了从 YAML 加载的配置以及被解析后的 AST
type CompiledRule struct {
	RuleConfig
	AST Node
}

// ResponseData 存储从HTTP响应中提取的关键信息
type ResponseData struct {
	Headers string
	Body    string
	Hash    string // Icon Hash
	//前三个用于给Banner使用
	BodyLength int
	Cert       string
	Title      string
	ICP        string
	Host       string // 用于存储请求的主机名或IP地址
	//FoundDomain string
	//FoundIP     string
}

// MatchedResult 存储匹配成功的结果
type MatchedResult struct {
	Name string
	Rank int
	URL  string
}

// LoadRulesFromFile 从指定的 YAML 文件路径加载并编译所有规则
func LoadRulesFromFile(filepath string) ([]CompiledRule, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file %s: %w", filepath, err)
	}

	var configs []RuleConfig
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	var compiledRules []CompiledRule
	for _, config := range configs {
		// 复用之前的表达式解析器
		ast, err := parseExpression(config.Expression)
		if err != nil {
			// 添加详细错误信息
			fmt.Printf("⚠️ Warning: Skipping rule '%s' due to parsing error\n", config.Name)
			fmt.Printf("  Expression: %s\n", config.Expression)
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		compiledRules = append(compiledRules, CompiledRule{
			RuleConfig: config,
			AST:        ast,
		})
	}
	return compiledRules, nil
}

// ============================================================================
// SECTION 2: Parser Engine (Lexer, AST, Parser, Evaluator)
// ============================================================================

// TokenType, Token, Lexer...
type TokenType int

const (
	TokenError TokenType = iota
	TokenEOF
	TokenIdentifier
	TokenString
	TokenAnd
	TokenOr
	TokenEquals
	TokenNotEquals // 新增 != 操作符
	TokenLParen
	TokenRParen
)

type Token struct {
	Type  TokenType
	Value string
	Pos   int // 添加位置信息
}

type Lexer struct {
	input string
	pos   int
}

func NewLexer(input string) *Lexer { return &Lexer{input: input} }

// 添加辅助方法，获取当前行和列信息
func (l *Lexer) getPositionContext(pos int) string {
	if pos >= len(l.input) {
		return "end of input"
	}

	start := pos - 20
	if start < 0 {
		start = 0
	}
	end := pos + 20
	if end > len(l.input) {
		end = len(l.input)
	}

	context := l.input[start:end]
	pointerPos := pos - start

	// 创建指向错误位置的指针
	pointer := strings.Repeat(" ", pointerPos) + "^"

	return fmt.Sprintf("...%s...\n%s", context, pointer)
}

func (l *Lexer) nextToken() Token {
	l.skipWhitespace()
	if l.pos >= len(l.input) {
		return Token{Type: TokenEOF, Pos: l.pos}
	}
	char := l.input[l.pos]
	switch char {
	case '=':
		// 检查是否是 == 或 =
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
			l.pos += 2
			return Token{Type: TokenEquals, Value: "==", Pos: l.pos - 2}
		}
		l.pos++
		return Token{Type: TokenEquals, Value: "=", Pos: l.pos - 1}
	case '!':
		// 检查是否是 !=
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
			l.pos += 2
			return Token{Type: TokenNotEquals, Value: "!=", Pos: l.pos - 2}
		}
		errMsg := fmt.Sprintf("非法字符 '!' (0x21) 在位置 %d", l.pos)
		errMsg += "\n" + l.getPositionContext(l.pos)
		return Token{Type: TokenError, Value: errMsg, Pos: l.pos}
	case '(':
		l.pos++
		return Token{Type: TokenLParen, Value: "(", Pos: l.pos - 1}
	case ')':
		l.pos++
		return Token{Type: TokenRParen, Value: ")", Pos: l.pos - 1}
	case '&':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '&' {
			l.pos += 2 //直接吃两个
			return Token{Type: TokenAnd, Value: "&&", Pos: l.pos - 2}
		}
	case '|':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '|' {
			l.pos += 2
			return Token{Type: TokenOr, Value: "||", Pos: l.pos - 2}
		}
	case '"':
		return l.readString()
	default:
		if unicode.IsLetter(rune(char)) || char == '<' || char == '>' {
			return l.readIdentifier()
		}
	}

	// 创建详细的错误信息
	errMsg := fmt.Sprintf("非法字符 '%c' (0x%02x) 在位置 %d", char, char, l.pos)
	errMsg += "\n" + l.getPositionContext(l.pos)
	return Token{Type: TokenError, Value: errMsg, Pos: l.pos}
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(rune(l.input[l.pos])) {
		l.pos++
	}
}

func (l *Lexer) readIdentifier() Token {
	start := l.pos
	for l.pos < len(l.input) {
		char := l.input[l.pos]
		// 允许字母、数字、下划线和特殊符号
		if unicode.IsLetter(rune(char)) || unicode.IsDigit(rune(char)) ||
			char == '_' || char == '<' || char == '>' || char == '/' ||
			char == ':' || char == '.' || char == '-' {
			l.pos++
		} else {
			break
		}
	}
	return Token{Type: TokenIdentifier, Value: l.input[start:l.pos], Pos: start}
}

func (l *Lexer) readString() Token {
	start := l.pos
	l.pos++ // 跳过起始引号
	var sb strings.Builder

	for l.pos < len(l.input) {
		if l.input[l.pos] == '"' {
			l.pos++ // 跳过结束引号
			return Token{Type: TokenString, Value: sb.String(), Pos: start}
		}

		// 处理转义引号
		if l.input[l.pos] == '\\' && l.pos+1 < len(l.input) {
			nextChar := l.input[l.pos+1]
			if nextChar == '"' || nextChar == '\\' {
				sb.WriteByte(nextChar)
				l.pos += 2
				continue
			}
		}

		sb.WriteByte(l.input[l.pos])
		l.pos++
	}

	// 未终止的字符串错误
	errMsg := fmt.Sprintf("未终止的字符串文本，起始位置: %d", start)
	errMsg += "\n" + l.getPositionContext(start)
	return Token{Type: TokenError, Value: errMsg, Pos: start}
}

// AST Nodes...
type Node interface{ Eval(data *ResponseData) bool }
type ConditionNode struct {
	Field    string
	Value    string
	Operator TokenType // 添加操作符字段
}

func (c *ConditionNode) Eval(data *ResponseData) bool {
	var targetValue string
	switch c.Field {
	case "body":
		targetValue = data.Body
	case "header":
		targetValue = data.Headers
	case "hash":
		targetValue = data.Hash
	default:
		return false
	}

	// 根据操作符进行不同的判断
	switch c.Operator {
	// TODO: 单独采取的是字符串包含判断,有点过于理想化了,后面可以优化优化
	case TokenEquals:
		return strings.Contains(targetValue, c.Value)
	case TokenNotEquals:
		return !strings.Contains(targetValue, c.Value)
	default:
		return false
	}
}

type BinaryOpNode struct {
	Operator    TokenType
	Left, Right Node
}

func (b *BinaryOpNode) Eval(data *ResponseData) bool {
	leftResult := b.Left.Eval(data)
	switch b.Operator {
	case TokenAnd:
		return leftResult && b.Right.Eval(data)
	case TokenOr:
		return leftResult || b.Right.Eval(data)
	}
	return false
}

// Parser...
type Parser struct {
	tokens []Token
	pos    int
}

func NewParser(tokens []Token) *Parser { return &Parser{tokens: tokens} }
func (p *Parser) current() Token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return Token{Type: TokenEOF}
}
func (p *Parser) advance() {
	if p.pos < len(p.tokens) {
		p.pos++
	}
}
func (p *Parser) expect(tt TokenType) (Token, error) {
	if p.current().Type == tt {
		t := p.current()
		p.advance()
		return t, nil
	}
	return Token{}, fmt.Errorf("语法错误: 期望 %v, 但得到 %v (位置: %d)",
		tt, p.current().Type, p.current().Pos)
}
func (p *Parser) Parse() (Node, error) {
	n, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	if p.current().Type != TokenEOF {
		return nil, fmt.Errorf("语法错误: 表达式尾部有多余内容 '%s' (位置: %d)",
			p.current().Value, p.current().Pos)
	}
	return n, nil
}
func (p *Parser) parseExpression() (Node, error) {
	l, e := p.parseTerm()
	if e != nil {
		return nil, e
	}
	for p.current().Type == TokenOr {
		op := p.current()
		p.advance()
		r, e := p.parseTerm()
		if e != nil {
			return nil, e
		}
		l = &BinaryOpNode{op.Type, l, r}
	}
	return l, nil
}
func (p *Parser) parseTerm() (Node, error) {
	l, e := p.parseFactor()
	if e != nil {
		return nil, e
	}
	for p.current().Type == TokenAnd {
		op := p.current()
		p.advance()
		r, e := p.parseFactor()
		if e != nil {
			return nil, e
		}
		l = &BinaryOpNode{op.Type, l, r}
	}
	return l, nil
}
func (p *Parser) parseFactor() (Node, error) {
	if p.current().Type == TokenLParen {
		p.advance()
		n, e := p.parseExpression()
		if e != nil {
			return nil, e
		}
		if _, e := p.expect(TokenRParen); e != nil {
			return nil, e
		}
		return n, nil
	}
	return p.parseCondition()
}
func (p *Parser) parseCondition() (Node, error) {
	ident, err := p.expect(TokenIdentifier)
	if err != nil {
		return nil, err
	}
	// 只保留原始字段：body, header, hash
	validFields := map[string]bool{"body": true, "header": true, "hash": true}
	if !validFields[ident.Value] {
		return nil, fmt.Errorf("无效字段名: '%s' (位置: %d)", ident.Value, ident.Pos)
	}

	// 检查操作符类型（= 或 !=）
	var operator TokenType
	switch p.current().Type {
	case TokenEquals:
		operator = TokenEquals
		p.advance()
	case TokenNotEquals:
		operator = TokenNotEquals
		p.advance()
	default:
		return nil, fmt.Errorf("语法错误: 期望 = 或 !=, 但得到 %v (位置: %d)",
			p.current().Type, p.current().Pos)
	}

	str, err := p.expect(TokenString)
	if err != nil {
		return nil, err
	}

	return &ConditionNode{
		Field:    ident.Value,
		Value:    str.Value,
		Operator: operator,
	}, nil
}

// parseExpression 是一个辅助函数，封装了完整的词法和语法分析过程
func parseExpression(expression string) (Node, error) {
	lexer := NewLexer(expression)
	var tokens []Token
	for {
		tok := lexer.nextToken()
		if tok.Type == TokenError {
			return nil, fmt.Errorf("词法错误: %s", tok.Value)
		}
		tokens = append(tokens, tok)
		if tok.Type == TokenEOF {
			break
		}
	}
	parser := NewParser(tokens)
	return parser.Parse()
}

func main() {
	//yamlPath := "fingerprints_fixed.yaml"
	yamlPath := "special.yaml"
	//host := "http://localhost:8080" //对这个host进行扫描探测
	fmt.Printf("🔍 Loading rules from %s \n", yamlPath)
	rules, err := LoadRulesFromFile(yamlPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("✅  Initial successfully,Loaded %d rules successfully.\n", len(rules))
	//for _, rule := range rules {
	//	url := host + rule.Path
	//	var sender Sender = &rule
	//	responseData, err := sender.Request(url, nil)
	//	if err != nil {
	//		log.Println("发包错误: " + err.Error())
	//	}
	//}
}

var compiledRule []CompiledRule

func init() {
	//初始化
}
