package cron

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"vault_util/common/execute"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

var cronTmpFileName string

func init() {
	cronTmpFileName = "myCron"
}

func PutEntryInCron(cronString, executableFileNameWithPath, subCommandsAndArguments string) (err error) {

	cronFileNameWithPath := filepath.Join(removeSpecifiedChildrenFromFilePath(executableFileNameWithPath, 1), cronTmpFileName)

	crontabOutput, err := execute.ExecuteCommandAndGetOutputAsString(getCommandForCronTab())
	if err != nil {
		return
	}

	crontabOutputSlice := strings.Split(crontabOutput, "\n")
	newFileContent := ""
	for _, currentLine := range crontabOutputSlice {
		if !strings.Contains(currentLine, executableFileNameWithPath) {
			newFileContent += (currentLine + "\n")
		}
	}

	newFileContent = strings.Trim(newFileContent, "\n")

	newFileContent += ("\n\n" + cronString + " export PATH=$PATH:" + SBIN_PATH + ";" + executableFileNameWithPath + " " + subCommandsAndArguments + "\n")

	err = ioutil.WriteFile(cronFileNameWithPath, []byte(newFileContent), 0777)
	if err != nil {
		return errors.Wrap(err, "Error in writing the contents to file : "+cronFileNameWithPath)
	}

	_, err = execute.ExecuteCommandAndGetOutputAsString(getCommandForCronTabEntry(cronFileNameWithPath))
	if err != nil {
		return
	}

	err = os.Remove(cronFileNameWithPath)
	if err != nil {
		log.Println("Error in removing the file : ", cronFileNameWithPath)
	}

	return
}

func getCommandForCronTab() (output string) {
	output = "crontab -l"
	return
}

func getCommandForCronTabEntry(fileName string) (output string) {
	output = "crontab " + fileName
	return
}

func removeSpecifiedChildrenFromFilePath(inputFilePath string, childLevel int) (output string) {
	filePathSlice := strings.Split(inputFilePath, "/")
	filePathSlice = filePathSlice[:len(filePathSlice)-childLevel]
	filePathSlice[0] = "/" + filePathSlice[0]

	for _, currentFilePath := range filePathSlice {
		output = filepath.Join(output, currentFilePath)
	}

	return
}
