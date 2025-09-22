package migrate

import (
	"go/ast"
	"strings"
)

// Transformer represents a code transformation
type Transformer interface {
	Transform(node ast.Node) bool
	Name() string
	Description() string
}

// ImportTransformer transforms import statements
type ImportTransformer struct {
	mappings map[string]string
}

// NewImportTransformer creates a new import transformer
func NewImportTransformer() *ImportTransformer {
	return &ImportTransformer{
		mappings: map[string]string{
			"github.com/gibson-sec/gibson-framework/shared":        "github.com/zero-day-ai/gibson-sdk/pkg/plugin",
			"github.com/gibson-sec/gibson-framework/shared/models": "github.com/zero-day-ai/gibson-sdk/pkg/core/models",
			"github.com/gibson-sec/gibson-framework/shared/types":  "github.com/zero-day-ai/gibson-sdk/pkg/plugin",
			"github.com/gibson-sec/gibson-framework/shared/errors": "github.com/zero-day-ai/gibson-sdk/pkg/core/models",
			"github.com/gibson-sec/gibson-framework/shared/utils":  "github.com/zero-day-ai/gibson-sdk/pkg/validation",
		},
	}
}

func (t *ImportTransformer) Name() string {
	return "ImportTransformer"
}

func (t *ImportTransformer) Description() string {
	return "Updates import statements from shared package to SDK"
}

func (t *ImportTransformer) Transform(node ast.Node) bool {
	file, ok := node.(*ast.File)
	if !ok {
		return false
	}

	modified := false
	for _, imp := range file.Imports {
		if imp.Path != nil {
			path := strings.Trim(imp.Path.Value, `"`)
			if newPath, exists := t.mappings[path]; exists {
				imp.Path.Value = `"` + newPath + `"`
				modified = true
			}
		}
	}

	return modified
}

// ResultTransformer transforms (T, error) returns to Result[T]
type ResultTransformer struct{}

func (t *ResultTransformer) Name() string {
	return "ResultTransformer"
}

func (t *ResultTransformer) Description() string {
	return "Converts (T, error) returns to Result[T] pattern"
}

func (t *ResultTransformer) Transform(node ast.Node) bool {
	modified := false

	ast.Inspect(node, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.FuncDecl:
			if t.transformFunctionSignature(decl) {
				modified = true
			}
			if t.transformFunctionBody(decl) {
				modified = true
			}
		}
		return true
	})

	return modified
}

func (t *ResultTransformer) transformFunctionSignature(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}

	// Check if last return type is error
	results := fn.Type.Results.List
	if len(results) >= 2 {
		lastResult := results[len(results)-1]
		if ident, ok := lastResult.Type.(*ast.Ident); ok && ident.Name == "error" {
			// Transform to Result[T]
			firstResult := results[0]

			// Create Result[T] type
			resultType := &ast.IndexExpr{
				X: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "models"},
					Sel: &ast.Ident{Name: "Result"},
				},
				Index: firstResult.Type,
			}

			// Replace the two return types with single Result[T]
			fn.Type.Results.List = []*ast.Field{
				{
					Type: resultType,
				},
			}

			return true
		}
	}

	return false
}

func (t *ResultTransformer) transformFunctionBody(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}

	modified := false

	// Transform return statements
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ret, ok := n.(*ast.ReturnStmt); ok {
			if t.transformReturnStatement(ret) {
				modified = true
			}
		}
		return true
	})

	return modified
}

func (t *ResultTransformer) transformReturnStatement(ret *ast.ReturnStmt) bool {
	if len(ret.Results) != 2 {
		return false
	}

	// Check if second result is nil or error
	secondResult := ret.Results[1]

	if ident, ok := secondResult.(*ast.Ident); ok && ident.Name == "nil" {
		// Transform return value, nil to models.Ok(value)
		ret.Results = []ast.Expr{
			&ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "models"},
					Sel: &ast.Ident{Name: "Ok"},
				},
				Args: []ast.Expr{ret.Results[0]},
			},
		}
		return true
	} else {
		// Transform return nil, err to models.Err[T](err)
		ret.Results = []ast.Expr{
			&ast.CallExpr{
				Fun: &ast.IndexExpr{
					X: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "Err"},
					},
					Index: &ast.Ident{Name: "T"}, // This would need type inference
				},
				Args: []ast.Expr{secondResult},
			},
		}
		return true
	}
}

// InterfaceTransformer updates plugin interface implementations
type InterfaceTransformer struct{}

func (t *InterfaceTransformer) Name() string {
	return "InterfaceTransformer"
}

func (t *InterfaceTransformer) Description() string {
	return "Updates plugin interface method signatures"
}

func (t *InterfaceTransformer) Transform(node ast.Node) bool {
	modified := false

	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			if t.isPluginMethod(fn) && t.updateMethodSignature(fn) {
				modified = true
			}
		}
		return true
	})

	return modified
}

func (t *InterfaceTransformer) isPluginMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil {
		return false
	}

	pluginMethods := map[string]bool{
		"GetInfo":    true,
		"Initialize": true,
		"Validate":   true,
		"Execute":    true,
		"Cleanup":    true,
	}

	return pluginMethods[fn.Name.Name]
}

func (t *InterfaceTransformer) updateMethodSignature(fn *ast.FuncDecl) bool {
	methodSignatures := map[string]func(*ast.FuncDecl) bool{
		"GetInfo":    t.updateGetInfoSignature,
		"Initialize": t.updateInitializeSignature,
		"Validate":   t.updateValidateSignature,
		"Execute":    t.updateExecuteSignature,
		"Cleanup":    t.updateCleanupSignature,
	}

	if updater, exists := methodSignatures[fn.Name.Name]; exists {
		return updater(fn)
	}

	return false
}

func (t *InterfaceTransformer) updateGetInfoSignature(fn *ast.FuncDecl) bool {
	// GetInfo() models.Result[models.PluginInfo]
	fn.Type.Params = &ast.FieldList{List: []*ast.Field{}}
	fn.Type.Results = &ast.FieldList{
		List: []*ast.Field{
			{
				Type: &ast.IndexExpr{
					X: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "Result"},
					},
					Index: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "PluginInfo"},
					},
				},
			},
		},
	}
	return true
}

func (t *InterfaceTransformer) updateInitializeSignature(fn *ast.FuncDecl) bool {
	// Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool]
	fn.Type.Params = &ast.FieldList{
		List: []*ast.Field{
			{
				Names: []*ast.Ident{{Name: "ctx"}},
				Type: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "context"},
					Sel: &ast.Ident{Name: "Context"},
				},
			},
			{
				Names: []*ast.Ident{{Name: "config"}},
				Type: &ast.MapType{
					Key:   &ast.Ident{Name: "string"},
					Value: &ast.InterfaceType{Methods: &ast.FieldList{}},
				},
			},
		},
	}
	fn.Type.Results = &ast.FieldList{
		List: []*ast.Field{
			{
				Type: &ast.IndexExpr{
					X: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "Result"},
					},
					Index: &ast.Ident{Name: "bool"},
				},
			},
		},
	}
	return true
}

func (t *InterfaceTransformer) updateValidateSignature(fn *ast.FuncDecl) bool {
	// Validate(ctx context.Context, request models.AssessRequest) models.Result[bool]
	fn.Type.Params = &ast.FieldList{
		List: []*ast.Field{
			{
				Names: []*ast.Ident{{Name: "ctx"}},
				Type: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "context"},
					Sel: &ast.Ident{Name: "Context"},
				},
			},
			{
				Names: []*ast.Ident{{Name: "request"}},
				Type: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "models"},
					Sel: &ast.Ident{Name: "AssessRequest"},
				},
			},
		},
	}
	fn.Type.Results = &ast.FieldList{
		List: []*ast.Field{
			{
				Type: &ast.IndexExpr{
					X: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "Result"},
					},
					Index: &ast.Ident{Name: "bool"},
				},
			},
		},
	}
	return true
}

func (t *InterfaceTransformer) updateExecuteSignature(fn *ast.FuncDecl) bool {
	// Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse]
	fn.Type.Params = &ast.FieldList{
		List: []*ast.Field{
			{
				Names: []*ast.Ident{{Name: "ctx"}},
				Type: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "context"},
					Sel: &ast.Ident{Name: "Context"},
				},
			},
			{
				Names: []*ast.Ident{{Name: "request"}},
				Type: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "models"},
					Sel: &ast.Ident{Name: "AssessRequest"},
				},
			},
		},
	}
	fn.Type.Results = &ast.FieldList{
		List: []*ast.Field{
			{
				Type: &ast.IndexExpr{
					X: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "Result"},
					},
					Index: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "AssessResponse"},
					},
				},
			},
		},
	}
	return true
}

func (t *InterfaceTransformer) updateCleanupSignature(fn *ast.FuncDecl) bool {
	// Cleanup(ctx context.Context) models.Result[bool]
	fn.Type.Params = &ast.FieldList{
		List: []*ast.Field{
			{
				Names: []*ast.Ident{{Name: "ctx"}},
				Type: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "context"},
					Sel: &ast.Ident{Name: "Context"},
				},
			},
		},
	}
	fn.Type.Results = &ast.FieldList{
		List: []*ast.Field{
			{
				Type: &ast.IndexExpr{
					X: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "models"},
						Sel: &ast.Ident{Name: "Result"},
					},
					Index: &ast.Ident{Name: "bool"},
				},
			},
		},
	}
	return true
}

// TypeTransformer updates type references
type TypeTransformer struct {
	typeMappings map[string]string
}

func NewTypeTransformer() *TypeTransformer {
	return &TypeTransformer{
		typeMappings: map[string]string{
			"shared.PluginInfo":      "models.PluginInfo",
			"shared.Target":          "models.Target",
			"shared.AssessRequest":   "models.AssessRequest",
			"shared.AssessResponse":  "models.AssessResponse",
			"shared.Finding":         "models.Finding",
			"shared.Payload":         "models.Payload",
			"shared.SecurityDomain":  "plugin.SecurityDomain",
			"shared.PayloadCategory": "plugin.PayloadCategory",
			"shared.PayloadType":     "plugin.PayloadType",
			"shared.Severity":        "plugin.Severity",
		},
	}
}

func (t *TypeTransformer) Name() string {
	return "TypeTransformer"
}

func (t *TypeTransformer) Description() string {
	return "Updates type references from shared package to SDK"
}

func (t *TypeTransformer) Transform(node ast.Node) bool {
	modified := false

	ast.Inspect(node, func(n ast.Node) bool {
		switch expr := n.(type) {
		case *ast.SelectorExpr:
			if t.updateSelectorExpr(expr) {
				modified = true
			}
		}
		return true
	})

	return modified
}

func (t *TypeTransformer) updateSelectorExpr(expr *ast.SelectorExpr) bool {
	if ident, ok := expr.X.(*ast.Ident); ok {
		oldType := ident.Name + "." + expr.Sel.Name
		if newType, exists := t.typeMappings[oldType]; exists {
			parts := strings.Split(newType, ".")
			if len(parts) == 2 {
				ident.Name = parts[0]
				expr.Sel.Name = parts[1]
				return true
			}
		}
	}
	return false
}

// CommentTransformer updates comments and documentation
type CommentTransformer struct{}

func (t *CommentTransformer) Name() string {
	return "CommentTransformer"
}

func (t *CommentTransformer) Description() string {
	return "Updates comments to reference SDK instead of shared package"
}

func (t *CommentTransformer) Transform(node ast.Node) bool {
	file, ok := node.(*ast.File)
	if !ok {
		return false
	}

	modified := false

	for _, commentGroup := range file.Comments {
		for _, comment := range commentGroup.List {
			originalText := comment.Text
			newText := strings.ReplaceAll(originalText, "shared package", "Gibson Plugin SDK")
			newText = strings.ReplaceAll(newText, "gibson-framework/shared", "gibson-plugin-sdk")

			if newText != originalText {
				comment.Text = newText
				modified = true
			}
		}
	}

	return modified
}
