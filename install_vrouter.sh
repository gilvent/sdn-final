# Wait for ONOS to be ready (OpenFlow port)
echo "Waiting for ONOS to be ready (port 6653)..."
until nc -z localhost 6653 2>/dev/null; do
  sleep 2
done
echo "ONOS is ready!"
cd vrouter

# Load vRouter configuration to ONOS
onos-netcfg localhost config.json
echo "vRouter configuration loaded!"

echo "Wait for a few seconds before building vrouter app..."
sleep 10

# Build and install vrouter app
echo "Building and installing vrouter app..."

mvn clean install -DskipTests -q

onos-app localhost install! target/vrouter-1.0-SNAPSHOT.oar
echo "vrouter app installed!"


