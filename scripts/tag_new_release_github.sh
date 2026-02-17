#!/bin/bash
FILE=getAppInfo.sh
if [[ -f "$FILE" ]]; then
  echo "## will execute $FILE"
	# shellcheck disable=SC1090
	source $FILE
elif [[ -f "./scripts/${FILE}" ]]; then
  echo "## will execute ./scripts/$FILE"
  # shellcheck disable=SC1090
  source ./scripts/$FILE
else
  echo "-- ERROR getAppInfo.sh was not found"
  exit 1
fi
echo "## APP: ${APP_NAME}, version: ${APP_VERSION} detected in file server.go"
if output=$(git status --porcelain) && [[ -z "$output" ]]; then
  if [[ -n $(git tag -l "v$APP_VERSION") ]]; then
    echo "## 💥💥 ERROR: \"${APP_NAME} tag ${APP_VERSION} \" already exist !" >&2
  else
    echo "## ✓🚀 OK: ${APP_NAME} tag ${APP_VERSION}  was not found ! So let's add this tag..."
    git tag "v$APP_VERSION" -m "v$APP_VERSION bump"
    echo "## ✓🚀 OK: ${APP_NAME} tag ${APP_VERSION}  will push to origin ..."
    git push origin --tags
  fi
else
  echo "## 💥💥 ERROR: ${APP_NAME} source tree is DIRTY YOU MUST commit your code before doing a tag ${APP_VERSION} !" >&2
  git status
fi



