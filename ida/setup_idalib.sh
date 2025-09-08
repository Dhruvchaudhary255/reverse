#!/bin/bash

IDA_PATH="/Applications/IDA Essential 9.2.app/Contents/MacOS"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

if [ -d "$IDA_PATH" ]; then
    echo -e "${GREEN}✓ Found IDA Essential 9.2 at: $IDA_PATH${NC}"
else
    echo -e "${RED}✗ IDA not found at: $IDA_PATH${NC}"
    echo "Please update IDA_PATH in this script"
    exit 1
fi

IDALIB_DIR="$IDA_PATH/idalib"

if [ ! -d "$IDALIB_DIR" ]; then
    echo -e "${RED}✗ idalib directory not found${NC}"
    echo "Expected at: $IDALIB_DIR"
    echo "For IDA Essential 9.2, it should be at: /Applications/IDA Essential 9.2.app/Contents/MacOS/idalib"
    exit 1
fi

echo -e "${GREEN}✓ Found idalib at: $IDALIB_DIR${NC}"

echo ""
echo "Step 1: Installing idalib Python package..."
if pip install "$IDALIB_DIR/python" 2>/dev/null; then
    echo -e "${GREEN}✓ idalib Python package installed${NC}"
else
    echo -e "${YELLOW}⚠ idalib might already be installed or installation failed${NC}"
fi

echo ""
echo "Step 2: Activating idalib..."
ACTIVATE_SCRIPT="$IDA_PATH/idalib/python/py-activate-idalib.py"

if [ ! -f "$ACTIVATE_SCRIPT" ]; then
    echo -e "${RED}✗ py-activate-idalib.py not found${NC}"
    echo "Expected at: $ACTIVATE_SCRIPT"
    exit 1
fi

echo "Running: python $ACTIVATE_SCRIPT -d $IDA_PATH"
if python "$ACTIVATE_SCRIPT" -d "$IDA_PATH"; then
    echo -e "${GREEN}✓ idalib activated successfully${NC}"
else
    echo -e "${RED}✗ Failed to activate idalib${NC}"
    exit 1
fi

echo ""
echo "Step 3: Testing idalib import..."
if python -c "import idapro; print('✓ idalib imported successfully')" 2>/dev/null; then
    echo -e "${GREEN}✓ idalib is ready to use${NC}"
else
    echo -e "${RED}✗ Failed to import idalib${NC}"
    echo "You may need to check your Python environment"
    exit 1
fi

# Create a simple test script
echo ""
echo "Creating test script: test_idalib.py"
cat > test_idalib.py << 'EOF'
#!/usr/bin/env python3
"""Test idalib installation"""

try:
    import idapro
    print("✓ idapro module imported")
    
    import ida_auto
    print("✓ ida_auto module imported")
    
    import ida_funcs
    print("✓ ida_funcs module imported")
    
    import ida_name
    print("✓ ida_name module imported")
    
    print("\n✅ All idalib modules imported successfully!")
    print("You can now run: python idalib_analyze.py <binary>")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\nTroubleshooting:")
    print("1. Make sure you ran this setup script")
    print("2. Check that you're using the same Python environment")
    print("3. Try running: python /path/to/IDA/py-activate-idalib.py -d /path/to/IDA")
EOF

chmod +x test_idalib.py

echo ""
echo "================================"
echo "Setup Complete!"
echo "================================"
echo ""
echo "To test the installation:"
echo "  python test_idalib.py"
echo ""
echo "To analyze a binary:"
echo "  python idalib_analyze.py ../samples/TODO/libcocos-*.so"
echo ""
echo "To analyze all TODO samples:"
echo "  python idalib_analyze.py -b ../samples/TODO/"
