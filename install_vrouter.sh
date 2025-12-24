# Wait for ONOS to be ready (OpenFlow port)
echo "Waiting for ONOS to be ready (port 6653)..."
until nc -z localhost 6653 2>/dev/null; do
  sleep 2
done
echo "ONOS is ready!"

# Load FPM configuration
# echo "Loading FPM configuration into ONOS..."
# onos-netcfg localhost < fpm-config.json

# Build and install vrouter app
echo "Building and installing vrouter app..."
cd vrouter
mvn clean install -DskipTests -q

onos-app localhost install! target/vrouter-1.0-SNAPSHOT.oar
echo "vrouter app installed!"

# Load vRouter configuration to ONOS
onos-netcfg localhost config.json