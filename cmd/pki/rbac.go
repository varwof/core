package main

import (
	"flag"
	"fmt"

	"github.com/varwof/core/internal"
)

func cmdRBAC(cfg *internal.Config, args []string) error {
	if len(args) == 0 {
		return showRBACMode(cfg)
	}
	switch args[0] {
	case "mode":
		return cmdRBACMode(cfg, args[1:])
	case "scope":
		return cmdRBACScope(cfg, args[1:])
	default:
		return fmt.Errorf("unknown rbac command: %s", args[0])
	}
}

func showRBACMode(cfg *internal.Config) error {
	mode := cfg.RBAC.PermissionMode
	if mode == "" {
		mode = "simple"
	}
	fmt.Printf("RBAC mode: %s\n", mode)
	fmt.Println("  simple     — development mode, no CA scope restrictions")
	fmt.Println("  enterprise — production mode, CA scope restrictions enforced")
	if mode == "enterprise" {
		fmt.Println()
		fmt.Println("Users without urn:pki:ca:* SAN will use config ca_scopes fallback.")
	}
	return nil
}

func cmdRBACMode(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("rbac mode", flag.ExitOnError)
	setEnterprise := fs.Bool("enterprise", false, "switch to enterprise mode")
	setSimple := fs.Bool("simple", false, "switch to simple mode")
	fs.Parse(args)

	if !*setEnterprise && !*setSimple {
		return showRBACMode(cfg)
	}

	if *setEnterprise && *setSimple {
		return fmt.Errorf("cannot set both --enterprise and --simple")
	}

	cfgPath, err := requireWriteConfig()
	if err != nil {
		return err
	}

	cfgMap, err := readRawConfig(cfgPath)
	if err != nil {
		return err
	}

	rbac, _ := cfgMap["rbac"].(map[string]interface{})
	if rbac == nil {
		rbac = make(map[string]interface{})
		cfgMap["rbac"] = rbac
	}

	if *setEnterprise {
		rbac["permission_mode"] = "enterprise"
		rbac["enabled"] = true
		fmt.Println("Switched to enterprise mode")
	} else if *setSimple {
		rbac["permission_mode"] = "simple"
		fmt.Println("Switched to simple mode")
	}

	if err := writeRawConfig(cfgPath, cfgMap); err != nil {
		return err
	}
	fmt.Printf("Config updated: %s\n", cfgPath)
	return nil
}

func cmdRBACScope(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("rbac scope", flag.ExitOnError)
	role := fs.String("role", "", bundle.T(curLang, "cli.flag_role"))
	scope := fs.String("scope", "", bundle.T(curLang, "cli.flag_scope"))
	list := fs.Bool("list", false, bundle.T(curLang, "cli.flag_list"))
	fs.Parse(args)

	if *role == "" && *scope == "" && !*list {
		return fmt.Errorf("usage: pki rbac scope --role <role> --scope <scope> [--list]")
	}

	// List mode: read from config (no write needed)
	if *list {
		cfgPath := configPath
		if cfgPath == "" {
			return fmt.Errorf("no config file found; use --config to specify")
		}
		cfgMap, err := readRawConfig(cfgPath)
		if err != nil {
			return err
		}
		rbac, _ := cfgMap["rbac"].(map[string]interface{})
		scopes, _ := rbac["ca_scopes"].(map[string]interface{})
		if scopes == nil {
			fmt.Println("No CA scopes configured.")
			return nil
		}
		fmt.Println("RBAC CA scopes (fallback for simple-to-enterprise migration):")
		for role, scopes := range scopes {
			fmt.Printf("  %s: %v\n", role, scopes)
		}
		return nil
	}

	// Write mode: require explicit --config
	cfgPath, err := requireWriteConfig()
	if err != nil {
		return err
	}

	cfgMap, err := readRawConfig(cfgPath)
	if err != nil {
		return err
	}

	rbac, _ := cfgMap["rbac"].(map[string]interface{})
	if rbac == nil {
		rbac = make(map[string]interface{})
		cfgMap["rbac"] = rbac
	}

	scopes, _ := rbac["ca_scopes"].(map[string]interface{})
	if scopes == nil {
		scopes = make(map[string]interface{})
		rbac["ca_scopes"] = scopes
	}

	var roleScopes []interface{}
	if existing, ok := scopes[*role]; ok {
		roleScopes, _ = existing.([]interface{})
	}

	for _, s := range roleScopes {
		if s.(string) == *scope {
			fmt.Printf("Scope %q already exists for role %q\n", *scope, *role)
			return nil
		}
	}

	roleScopes = append(roleScopes, *scope)
	scopes[*role] = roleScopes
	rbac["ca_scopes"] = scopes
	cfgMap["rbac"] = rbac

	if err := writeRawConfig(cfgPath, cfgMap); err != nil {
		return err
	}
	fmt.Printf("CA scope %q added for role %q\n", *scope, *role)
	fmt.Printf("Config: %s\n", cfgPath)
	return nil
}
