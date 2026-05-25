package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	commands "github.com/jakenoc/tinymesh0/internal/cli"
	"github.com/jakenoc/tinymesh0/internal/tm0d"
)

func main() {
	root := &cobra.Command{
		Use:   "tinymesh0d",
		Short: "tinymesh0 — a decentralized mesh VPN daemon",
	}

	var cfgFile string
	var webAddr string

	upCmd := &cobra.Command{
		Use:   "up",
		Short: "Bring up the tinymesh0 interface",
		RunE: func(_ *cobra.Command, _ []string) error {
			return tm0d.NewDaemon(cfgFile).Run()
		},
	}
	upCmd.Flags().StringVarP(&cfgFile, "config", "c", "tinymesh0.yaml", "path to config file")

	downCmd := &cobra.Command{
		Use:   "down",
		Short: "Take down the tinymesh0 interface",
		RunE: func(_ *cobra.Command, _ []string) error {
			return commands.RunDown()
		},
	}

	var openWeb bool
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show tinymesh0 interface status",
		RunE: func(_ *cobra.Command, _ []string) error {
			if openWeb {
				return commands.RunStatusWeb(webAddr)
			}
			return commands.RunStatus()
		},
	}
	statusCmd.Flags().BoolVar(&openWeb, "web", false, "open the topology UI in a browser")
	statusCmd.Flags().StringVar(&webAddr, "addr", "localhost:8080", "topology UI address (host:port)")

	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a WireGuard keypair",
		RunE: func(_ *cobra.Command, _ []string) error {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return err
			}
			fmt.Printf("private-key: %s\n", key)
			fmt.Printf("public-key:  %s\n", key.PublicKey())
			return nil
		},
	}

	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect or reload the mesh policy",
	}
	policyCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "Show the active iptables policy chain",
			RunE: func(_ *cobra.Command, _ []string) error {
				return commands.RunPolicyList()
			},
		},
		&cobra.Command{
			Use:   "reload",
			Short: "Signal the running daemon to reload its policy from config",
			RunE: func(_ *cobra.Command, _ []string) error {
				return commands.RunPolicyReload(tm0d.PidFile)
			},
		},
	)

	dnsCmd := &cobra.Command{
		Use:   "dns",
		Short: "Inspect mesh DNS state",
	}
	dnsCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "Show the hostname → mesh IP table",
			RunE: func(_ *cobra.Command, _ []string) error {
				return commands.RunDNSList()
			},
		},
	)

	root.AddCommand(upCmd, downCmd, statusCmd, keygenCmd, policyCmd, dnsCmd)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
