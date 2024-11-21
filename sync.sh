#!/bin/bash

# Fetch the pod name dynamically using a label selector (assuming the label is app=stelarapi)
POD_NAME=$(kubectl get pods -l app.kubernetes.io/component=stelarapi -o jsonpath='{.items[0].metadata.name}')

# Check if the POD_NAME is not empty
if [ -z "$POD_NAME" ]; then
  echo "Error: Pod not found"
  exit 1
fi

# Run kubectl cp to copy the source directory to the pod
kubectl cp ./src "$POD_NAME":/app/ -c apiserver

# Check if the copy command was successful
if [ $? -eq 0 ]; then
  echo "Files successfully synced with $POD_NAME:/app/"
else
  echo "Error: Failed to copy files"
  exit 1
fi
