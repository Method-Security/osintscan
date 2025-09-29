#!/bin/bash
set -e

# Script to process build artifacts and upload osintscan executables to S3
# Expects build artifacts to be available in ./artifacts/ directory

REPO_NAME="osintscan"

# Get version from environment or parameter
VERSION_CLEAN="${VERSION:-unknown}"
if [[ "$VERSION_CLEAN" == v* ]]; then
    VERSION_CLEAN="${VERSION_CLEAN#v}"
fi

echo "Processing version: $VERSION_CLEAN"

# Check if artifacts directory exists
if [ ! -d "artifacts" ]; then
    echo "No artifacts directory found. This script should run after downloading build artifacts."
    exit 1
fi

echo "=== Available artifacts ==="
find artifacts/ -type f -name "*osintscan*" | head -20

# Create S3 content directory structure
mkdir -p "s3_content/$REPO_NAME/$VERSION_CLEAN"

# Define platform mappings for artifact directories to S3 structure
# Format: "artifact_dir:s3_platform"
PLATFORM_MAPPINGS=(
    "linux-amd64-dist:linux-amd64"
    "linux-arm64-dist:linux-arm64"
    "macos-latest-dist:darwin-arm64"
    "windows-latest-dist:windows-amd64"
)

process_artifact_directory() {
    local artifact_dir="$1"
    local s3_platform="$2"

    echo "Processing $artifact_dir for platform $s3_platform..."

    # Create platform directory in S3 structure
    mkdir -p "s3_content/$REPO_NAME/$VERSION_CLEAN/$s3_platform"

    # Find the executable in the artifact directory
    local executable_path=""

    if [[ "$s3_platform" == "windows-amd64" ]]; then
        # Look for .exe file
        executable_path=$(find "artifacts/$artifact_dir" -name "${REPO_NAME}.exe" -type f | head -1)
        if [ -n "$executable_path" ]; then
            cp "$executable_path" "s3_content/$REPO_NAME/$VERSION_CLEAN/$s3_platform/${REPO_NAME}.exe"
            echo "Copied Windows executable for $s3_platform"
            return 0
        fi
    else
        # Look for Unix executable (no extension)
        executable_path=$(find "artifacts/$artifact_dir" -name "$REPO_NAME" -type f | head -1)
        if [ -n "$executable_path" ]; then
            cp "$executable_path" "s3_content/$REPO_NAME/$VERSION_CLEAN/$s3_platform/$REPO_NAME"
            chmod +x "s3_content/$REPO_NAME/$VERSION_CLEAN/$s3_platform/$REPO_NAME"
            echo "Copied Unix executable for $s3_platform"
            return 0
        fi
    fi

    echo "Could not find executable in $artifact_dir"
    return 1
}

# Process each platform
echo "=== Processing build artifacts ==="
success_count=0
for mapping in "${PLATFORM_MAPPINGS[@]}"; do
    artifact_dir="${mapping%:*}"
    s3_platform="${mapping#*:}"

    if [ -d "artifacts/$artifact_dir" ]; then
        if process_artifact_directory "$artifact_dir" "$s3_platform"; then
            success_count=$((success_count + 1))
        fi
    else
        echo "Warning: Artifact directory $artifact_dir not found, skipping $s3_platform"
    fi
done

if [ $success_count -eq 0 ]; then
    echo "No artifacts were successfully processed"
    exit 1
fi

echo "Successfully processed $success_count platform executables"

# Show what we've prepared for upload
echo "=== Prepared files for S3 upload ==="
find s3_content/ -type f -exec ls -la {} \;

# Upload to S3 if S3_BUCKET_URL is set
if [ -n "$S3_BUCKET_URL" ]; then
    echo "=== Uploading to S3 ==="
    echo "Uploading to S3 bucket: $S3_BUCKET_URL"

    # Upload to version-specific path with SHA256 checksums
    aws s3 sync "s3_content/$REPO_NAME/$VERSION_CLEAN/" "$S3_BUCKET_URL/$REPO_NAME/$VERSION_CLEAN/" --checksum-algorithm SHA256

    echo "✓ Successfully uploaded $REPO_NAME version $VERSION_CLEAN to S3"
else
    echo "S3_BUCKET_URL not set, skipping S3 upload"
    echo "Files are ready in s3_content/ directory"
fi

echo "=== Upload process completed ==="
