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
				Usage:   "Force IPv4 only, will not obey when fetch server list\n\t",
			},
			&cli.BoolFlag{
				Name:    defs.OptionIPv6,
				Aliases: []string{defs.OptionIPv6Alt},
				Usage:   "Force IPv6 only, will not obey when fetch server list\n\t",
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
				Usage: "Use 1024 bytes as 1 kilobyte instead of 1000",
			},
			&cli.BoolFlag{
				Name:    defs.OptionSimple,
				Aliases: []string{defs.OptionSimpleAlt},
				Usage:   "Suppress verbose output, only show basic information\n\t",
			},
			&cli.BoolFlag{
				Name: defs.OptionCSV,
				Usage: "Suppress verbose output, only show basic information in CSV\n" +
					"\tformat. Speeds listed in bit/s and not affected by --bytes\n\t",
			},
			&cli.StringFlag{
				Name: defs.OptionCSVDelimiter,
				Usage: "Single character delimiter (`CSV_DELIMITER`) to use in\n" +
					"\tCSV output.",
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
				Usage: "Specify a `SERVER` ID to test against. Can be supplied\n" +
					"\tmultiple times. Cannot be used with --exclude",
			},
			&cli.StringSliceFlag{
				Name:    defs.OptionProvince,
				Aliases: []string{defs.OptionProvinceAlt},
				Usage: "Specify a `PROVINCE` ID or Code to test against. Can be\n" +
					"\tsupplied multiple times.",
				Hidden: true,
			},
			&cli.StringSliceFlag{
				Name:    defs.OptionISP,
				Aliases: []string{defs.OptionISPAlt},
				Usage: "Specify a `ISP` ASN or Code to test against. Can be supplied\n" +
					"\tmultiple times.",
				Hidden: true,
			},
			&cli.StringSliceFlag{
				Name: defs.OptionExclude,
				Usage: "`EXCLUDE` a server from selection. Can be supplied\n" +
					"\tmultiple times. Cannot be used with --server",
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
				Usage: "HTTP `TIMEOUT` in seconds.",
				Value: 15,
			},
			&cli.IntFlag{
				Name:    defs.OptionDuration,
				Aliases: []string{defs.OptionDurationAlt},
				Usage:   "Upload and download test duration in seconds",
				Value:   15,
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
			&cli.BoolFlag{
				Name:    defs.OptionDisableTai,
				Aliases: []string{defs.OptionDisableTaiAlt},
				Usage:   "Don't use Global Speed servers",
			},
			&cli.BoolFlag{
				Name:    defs.OptionDisablePet,
				Aliases: []string{defs.OptionDisablePetAlt},
				Usage:   "Don't use Perception servers",
			},
			&cli.BoolFlag{
				Name:    defs.OptionDisableWir,
				Aliases: []string{defs.OptionDisableWirAlt},
				Usage:   "Don't use Wireless Speed servers",
			},
		},
	}

	// run main function with cli options
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("Terminated due to error")
	}
}
