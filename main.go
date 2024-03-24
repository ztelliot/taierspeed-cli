package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/ztelliot/taierspeed-cli/defs"
	"github.com/ztelliot/taierspeed-cli/speedtest"
)

// init sets up the essential bits on start up
func init() {
	// set logrus formatter and default log level
	formatter := &defs.NoFormatter{}

	// debug level is for --debug messages
	// info level is for non-suppress mode
	// warn level is for suppress modes
	// error level is for errors

	log.SetOutput(os.Stderr)
	log.SetFormatter(formatter)
	log.SetLevel(log.InfoLevel)
}

func main() {
	// define cli options
	app := &cli.App{
		Name:     "Taierspeed-cli",
		Usage:    "Test your Internet speed with TaierSpeed",
		Action:   speedtest.SpeedTest,
		HideHelp: true,
		Flags: []cli.Flag{
			cli.HelpFlag,
			&cli.BoolFlag{
				Name:    defs.OptionVersion,
				Aliases: []string{defs.OptionVersionAlt},
				Usage:   "Show the version number and exit",
			},
			&cli.BoolFlag{
				Name:    defs.OptionIPv4,
				Aliases: []string{defs.OptionIPv4Alt},
				Usage:   "Force IPv4 only",
			},
			&cli.BoolFlag{
				Name:    defs.OptionIPv6,
				Aliases: []string{defs.OptionIPv6Alt},
				Usage:   "Force IPv6 only",
			},
			&cli.BoolFlag{
				Name:   defs.OptionNoDownload,
				Usage:  "Do not perform download test",
				Hidden: true,
			},
			&cli.BoolFlag{
				Name:   defs.OptionNoUpload,
				Usage:  "Do not perform upload test",
				Hidden: true,
			},
			&cli.BoolFlag{
				Name: defs.OptionNoICMP,
				Usage: "Do not use ICMP ping. ICMP doesn't work well under Linux\n" +
					"\tat this moment, so you might want to disable it\n\t",
			},
			&cli.IntFlag{
				Name:    defs.OptionConcurrent,
				Aliases: []string{defs.OptionConcurrentAlt},
				Usage:   "Concurrent HTTP requests being made",
				Value:   3,
			},
			&cli.BoolFlag{
				Name: defs.OptionBytes,
				Usage: "Display values in bytes instead of bits. Does not affect\n" +
					"\toutput from --json or --csv",
			},
			&cli.BoolFlag{
				Name:  defs.OptionMebiBytes,
				Usage: "Use 1024 bytes as 1 kilobyte instead of 1000\n\t",
			},
			&cli.BoolFlag{
				Name:    defs.OptionSimple,
				Aliases: []string{defs.OptionSimpleAlt},
				Usage:   "Suppress verbose output, only show basic information\n\t",
			},
			&cli.BoolFlag{
				Name: defs.OptionCSV,
				Usage: "Suppress verbose output. Speeds listed in bit/s and not\n" +
					"\taffected by --bytes",
			},
			&cli.StringFlag{
				Name:  defs.OptionCSVDelimiter,
				Usage: "Single character delimiter to use in CSV output\n\t",
				Value: ",",
			},
			&cli.BoolFlag{
				Name:  defs.OptionCSVHeader,
				Usage: "Print CSV headers",
			},
			&cli.BoolFlag{
				Name: defs.OptionJSON,
				Usage: "Suppress verbose output. Speeds listed in bit/s and not\n" +
					"\taffected by --bytes",
			},
			&cli.BoolFlag{
				Name:    defs.OptionList,
				Aliases: []string{defs.OptionListAlt},
				Usage:   "Display a list of servers",
			},
			&cli.StringSliceFlag{
				Name:    defs.OptionServer,
				Aliases: []string{defs.OptionServerAlt},
				Usage: "Specify a server `ID` to test against. Can be supplied\n" +
					"\tmultiple times",
			},
			&cli.StringSliceFlag{
				Name:    defs.OptionServerGroup,
				Aliases: []string{defs.OptionServerGroupAlt},
				Usage: "Specify a `GROUP` of servers by PROVINCE@ISP to test.\n" +
					"\tCan be supplied multiple times.\n" +
					"\tPROVINCE refer to `GB/T 2260-2007` (bj, sh, gd... etc).\n" +
					"\tISP can be {ct, cu, cm, cernet, catv, drpeng} or `ASN`.\n" +
					"\tYou can use `lo` to refer to the current province or ISP",
			},
			&cli.StringSliceFlag{
				Name: defs.OptionExclude,
				Usage: "`EXCLUDE` a server from selection. Can be supplied\n" +
					"\tmultiple times",
			},
			&cli.StringFlag{
				Name: defs.OptionSource,
				Usage: "`SOURCE` IP address to bind to, will not obey when\n" +
					"\tfetch server list",
			},
			&cli.StringFlag{
				Name:    defs.OptionInterface,
				Aliases: []string{defs.OptionInterfaceAlt},
				Usage:   "Network `INTERFACE` to bind to, only available for linux",
			},
			&cli.IntFlag{
				Name:  defs.OptionTimeout,
				Usage: "HTTP `TIMEOUT` in seconds",
				Value: 15,
			},
			&cli.IntFlag{
				Name:    defs.OptionDuration,
				Aliases: []string{defs.OptionDurationAlt},
				Usage:   "Upload and download test duration in seconds\n\t",
				Value:   15,
				Hidden:  true,
			},
			&cli.IntFlag{
				Name:   defs.OptionUploadSize,
				Usage:  "Size of payload being uploaded in KiB",
				Value:  1024,
				Hidden: true,
			},
			&cli.BoolFlag{
				Name: defs.OptionNoPreAllocate,
				Usage: "Do not pre allocate upload data. Pre allocation is\n" +
					"\tenabled by default to improve upload performance. To\n" +
					"\tsupport systems with insufficient memory, use this\n" +
					"\toption to avoid out of memory errors",
			},
			&cli.BoolFlag{
				Name:    defs.OptionDebug,
				Aliases: []string{"verbose"},
				Usage:   "Debug mode (verbose logging)",
				Hidden:  true,
			},
		},
	}

	// run main function with cli options
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("Terminated due to error")
	}
}
