package main

import (
	"fmt"
	syslog "gopkg.in/mcuadros/go-syslog.v2"
	syslogclient "github.com/RackSec/srslog"
	"os"
)

type Syslog struct {
	Path   string
	Filter struct {
		Facility string
		facility int

		Severity string
		severity int
	}
	Output struct {
		Template string
	}
	ForwardingSocket struct {
		HostnamePort string
	}
}

var SyslogFacilityMap = map[string]int{
	"kern":         0,
	"user":         1,
	"mail":         2,
	"daemon":       3,
	"auth":         4,
	"syslog":       5,
	"lpr":          6,
	"news":         7,
	"uucp":         8,
	"cron":         9,
	"authpriv":     10,
	"ftp":          11,
	"ntp":          12,
	"security":     13,
	"console":      14,
	"solaris-cron": 15,
	"local0":       16,
	"local1":       17,
	"local2":       18,
	"local3":       19,
	"local4":       20,
	"local5":       21,
	"local6":       22,
	"local7":       23,
}

var SyslogPriorityMap = map[string]int{
	"emerg":     0,
	"emergency": 0,
	"alert":     1,
	"crit":      2,
	"critical":  2,
	"err":       3,
	"error":     3,
	"warn":      4,
	"warning":   4,
	"notice":    5,
	"info":      6,
	"dbg":       7,
	"debug":     7,
}

func handleSyslog() {
	LoggerStdout.Verbose(fmt.Sprintf(" -> starting syslog daemon (%s)", configuration.Syslog.Path))
	LoggerStdout.Verbose(fmt.Sprintf(" -> forwarding messages to remote syslog at (%s)", configuration.Syslog.ForwardingSocket.HostnamePort))

	// Check if syslog path exists, remove if already existing
	_, err := os.Stat(configuration.Syslog.Path)
	if err == nil {
		os.Remove(configuration.Syslog.Path)
	}

	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUnixgram(configuration.Syslog.Path)
	server.Boot()

	forwardingConn, err := syslogclient.Dial("tcp", configuration.Syslog.ForwardingSocket.HostnamePort, syslogclient.LOG_INFO, "test")
	if err != nil {
		fmt.Print("Error opening forwarding TCP socket")
		os.Exit(1)
	}




	go func(channel syslog.LogPartsChannel, w *syslogclient.Writer) {


		for logParts := range channel {
			facilityId := uint(logParts["facility"].(int))
			severityId := uint(logParts["severity"].(int))

			// facility filter
			if hasBit(configuration.Syslog.Filter.facility, facilityId) == false {
				continue
			}

			// severity filter
			if hasBit(configuration.Syslog.Filter.severity, severityId) == false {
				continue
			}

			// build message
			message := fmt.Sprintf("%s %s", logParts["hostname"], logParts["content"])

			// custom template
			if configuration.Syslog.Output.Template != "" {
				message = fmt.Sprintf(configuration.Syslog.Output.Template, message)
			}

			w.Info(message)
			LoggerStdout.Println(message)
		}
	}(channel, forwardingConn)

	server.Wait()
}
