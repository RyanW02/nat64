package nat64

import (
	"errors"
	"go.uber.org/zap"
	"os/exec"
	"slices"
)

type CommandSet struct {
	Commands []*Command
}

type Command struct {
	Cmd              *exec.Cmd
	AllowedExitCodes []int
}

func NewCommandSet(commands ...*Command) *CommandSet {
	return &CommandSet{
		Commands: commands,
	}
}

func NewCommand(cmd *exec.Cmd, allowedExitCodes ...int) *Command {
	return &Command{
		Cmd:              cmd,
		AllowedExitCodes: allowedExitCodes,
	}
}

func (cs *CommandSet) Run(logger *zap.Logger) error {
	for _, c := range cs.Commands {
		err := c.Run()
		if err != nil {
			logger.Error("Command failed", zap.String("cmd", c.Cmd.String()), zap.Error(err))
			return err
		}

		logger.Info("Command succeeded", zap.String("cmd", c.Cmd.String()))
	}

	return nil
}

func (c *Command) Run() error {
	err := c.Cmd.Run()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if slices.Contains(c.AllowedExitCodes, exitError.ExitCode()) {
				return nil
			}
		}

		return err
	}

	return nil
}
