package main

import (
	"fmt"
	"os"

	"github.com/anxiousmodernman/certnab"
	"github.com/urfave/cli"
)

var version = "0.1.0"

func main() {
	app := cli.NewApp()
	app.Version = version

	acmeServer := cli.StringFlag{
		Name:   "acme-server",
		Usage:  "ACME server to connect to; Let's Encrypt prod is acme-v01.api.letsencrypt.org",
		Value:  "acme-staging.api.letsencrypt.org",
		EnvVar: "CERTNAB_ACME_SERVER",
	}

	destDir := cli.StringFlag{
		Name:   "dest",
		Usage:  "Destination directory for cert.pem and key.pem",
		EnvVar: "CERTNAB_DEST",
	}

	domain := cli.StringFlag{
		Name:   "domain",
		Usage:  "Fully qualified domain name we are requesting a cert for",
		EnvVar: "CERTNAB_DOMAIN",
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:  "renew",
			Usage: "perform ACME exchange, if needed",
			Flags: []cli.Flag{acmeServer, destDir, domain},
			Action: func(ctx *cli.Context) error {
				srv := ctx.String("acme-server")
				dest := ctx.String("dest")
				dom := ctx.String("domain")
				c, err := certnab.NewClient(srv, dest, dom)
				if err != nil {
					return fmt.Errorf("client: %v", err)
				}
				return c.HTTPChallenge()
			},
		},
	}

	app.Run(os.Args)
}
