package com.stratio.mesos.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stratio.mesos.http.HTTPUtils;
import com.stratio.mesos.http.MesosInterface;
import net.thisptr.jackson.jq.JsonQuery;
import okhttp3.ResponseBody;
import org.apache.log4j.Logger;
import retrofit2.Call;
import retrofit2.Response;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

/**
 * Created by alonso on 20/06/17.
 */
public class MesosApi {
    final static Logger LOG = Logger.getLogger(MesosApi.class);

    private ObjectMapper MAPPER = new ObjectMapper();
    private MesosInterface mesosInterface;
    private String endpointsPrefix;

    public enum EndpointPrefix {
        MASTER, MESOS, EMPTY;

        @Override
        public String toString() {
            switch (this) {
                case MASTER: return "master";
                case MESOS: return "mesos";
                case EMPTY: return "";
                default: throw new IllegalArgumentException();
            }
        }
    }

    public MesosApi(String mesosMasterUrl) {
        this.endpointsPrefix = EndpointPrefix.EMPTY.toString();
        this.mesosInterface = HTTPUtils.buildBasicInterface(mesosMasterUrl, MesosInterface.class);
    }

    public MesosApi(String accessToken, String mesosMasterUrl) {
        this.endpointsPrefix = EndpointPrefix.EMPTY.toString();
        this.mesosInterface = HTTPUtils.buildTokenBasedInterface(accessToken, mesosMasterUrl, MesosInterface.class);
    }

    public MesosApi(String principal, String secret, String mesosMasterUrl) {
        this.endpointsPrefix = EndpointPrefix.EMPTY.toString();
        this.mesosInterface = HTTPUtils.buildSecretBasedInterface(principal, secret, mesosMasterUrl, MesosInterface.class);
    }

    public void setEndpointsPrefix(EndpointPrefix endpointsPrefix) {
        this.endpointsPrefix = endpointsPrefix.toString();
    }

    public String getEndpointsPrefix() {
        return endpointsPrefix;
    }

    public boolean hasEndpointPrefix() { return !endpointsPrefix.isEmpty(); }

    /**
     * Finds a list of resources for a specific role inside a mesos slave
     * @param role mesos role
     * @param slaveId mesos slave id
     * @return List of JSON resources
     */
    public String[] findResourcesFor(String role, String slaveId) {
        Call<ResponseBody> mesosCall;

        try {
            if (!hasEndpointPrefix()) mesosCall = mesosInterface.findResources();
            else mesosCall = mesosInterface.findResources(getEndpointsPrefix());

            Response<ResponseBody> response = mesosCall.execute();
            LOG.info("findResourcesFor " + response.message());
            if (response.code() == HTTPUtils.HTTP_OK_CODE) {
                JsonQuery q = JsonQuery.compile(".slaves[]|.id=\""+slaveId+"\"|.reserved_resources_full.\""+role+"\"[]?");
                JsonNode in = MAPPER.readTree(new String(response.body().bytes()));
                List<JsonNode> resources = q.apply(in);

                return resources.stream()
                        .map(resource->resource.toString())
                        .toArray(String[]::new);
            } else {
                LOG.info("Error to try fetch resources for cluster " + response.code() + " and message: " + response.errorBody());
                return null;
            }

        } catch (IOException e) {
            LOG.info("Unregister failure with message " + e.getMessage());
            return null;
        }
    }

    /**
     * Unreserves a specific resource for a given slaveId.
     * The JSON must be exactly as mesos expects, otherwise it won't be accepted yielding 409 - Conflict
     * @param slaveId mesos slave id
     * @param resourceJson exact resource JSON
     * @return mesos http return code
     */
    public int unreserveResourceFor(String slaveId, String resourceJson) {
        int code = -1;
        if (resourceJson==null || slaveId==null || resourceJson.isEmpty() || slaveId.isEmpty()) {
            LOG.error("Parameters 'slaveId' and 'resourceJson' cannot be empty or null");
            return code;
        }

        Call<ResponseBody> mesosCall;

        try {
            // non-disk resources
            if (!resourceJson.toLowerCase().replace(" ", "").contains("\"disk\":{\"persistence\"")) {

                if (!hasEndpointPrefix()) mesosCall = mesosInterface.unreserve(slaveId, "[" + resourceJson + "]");
                else mesosCall = mesosInterface.unreserve(getEndpointsPrefix(), slaveId, "[" + resourceJson + "]");

                Response<ResponseBody> execute = mesosCall.execute();
                code = execute.code();
                LOG.info("Unregister standard resource returned " + code);
            } else {
                code = unreserveVolumesFor(slaveId, resourceJson);
                LOG.info("Unregister volume resource returned " + code);
            }

            System.out.println(code);
            return code;
        } catch (Exception e) {
            LOG.info("Unregister failure with message " + e.getMessage());
            return -1;
        }
    }

    /**
     * Unreserves disk volumes from the specified slaveId
     * The JSON must be exactly as mesos expects, otherwise it won't be accepted yielding 409 - Conflict
     * @param slaveId mesos slave id
     * @param resourceJson disk resource json
     * @return mesos http return code
     */
    public int unreserveVolumesFor(String slaveId, String resourceJson) {
        if (resourceJson==null || slaveId==null || resourceJson.isEmpty() || slaveId.isEmpty()) {
            LOG.error("Parameters 'slaveId' and 'resourceJson' cannot be empty or null");
            return -1;
        }

        Call<ResponseBody> mesosCall;
        Response<ResponseBody> response;

        try {
            // destroy the volume
            if (!hasEndpointPrefix()) mesosCall = mesosInterface.destroyVolumes(slaveId, "[" + resourceJson + "]");
            else mesosCall = mesosInterface.destroyVolumes(getEndpointsPrefix(), slaveId, "[" + resourceJson + "]");
            response = mesosCall.execute();
            LOG.info("unreserveVolumesFor " + response.message());
            if (response.code() == HTTPUtils.UNRESERVE_OK_CODE) {
                // remove "disk" from JSON before unregistering resource
                HashMap<String,Object> result = MAPPER.readValue(resourceJson, HashMap.class);
                result.remove("disk");

                // unreserve the resource
                mesosCall = mesosInterface.unreserve(slaveId, "[" + MAPPER.writeValueAsString(result) + "]");
                response = mesosCall.execute();
            } else {
                LOG.error("Unable to destroy volume, resource ");
            }
            return response.code();
        } catch (IOException e) {
            LOG.info("Unregister failure with message " + e.getMessage());
            return -1;
        }
    }

    /**
     * Performs a teardown of the specified frameworkId. A teardown <b>does not</b> imply cleaning zookeeper configuration
     * @param frameworkId
     * @return
     */
    public boolean teardown(String frameworkId) {
        if (frameworkId==null || frameworkId.isEmpty()) {
            LOG.error("Parameter 'frameworkId' cannot be null or empty");
            return false;
        }

        Call<ResponseBody> mesosCall;
        try {
            if (!hasEndpointPrefix()) mesosCall = mesosInterface.teardown(frameworkId);
            else mesosCall = mesosInterface.teardown(getEndpointsPrefix(), frameworkId);
            Response<ResponseBody> response = mesosCall.execute();
            LOG.info("teardown " + response.message());
            return (response.code() == HTTPUtils.HTTP_OK_CODE);
        } catch (IOException e) {
            LOG.info("Unregister failure with message " + e.getMessage());
            return false;
        }
    }

    /**
     * Finds any frameworkId that matches the given serviceName, role and principal.
     * By default, it will only look for active frameworks
     * @param serviceName mesos service name
     * @param role mesos role
     * @param principal mesos principal
     * @return An optional list of framework ids
     */
    public Optional<String[]> findFrameworkId(String serviceName, String role, String principal) {
        return findFrameworkId(serviceName, role, principal, true);
    }

    /**
     * Finds any frameworkId that matches the given serviceName, role, principal and activation status
     * @param serviceName mesos service name
     * @param role mesos role
     * @param principal mesos principal
     * @param active filter by active/inactive frameworks
     * @return An optional list of framework ids
     */
    public Optional<String[]> findFrameworkId(String serviceName, String role, String principal, boolean active) {
        Call<ResponseBody> mesosCall;
        Optional<String[]> frameworkId = Optional.empty();

        try {
            if (!hasEndpointPrefix()) mesosCall = mesosInterface.findFrameworks();
            else mesosCall = mesosInterface.findFrameworks(getEndpointsPrefix());

            Response<ResponseBody> response = mesosCall.execute();
            LOG.info("findFrameworkId " + response.message());
            if (response.code() == HTTPUtils.HTTP_OK_CODE) {
                String includeInactives = active?" and .active==true":" and .active==false";
                JsonQuery q = JsonQuery.compile(".frameworks[]|select(.name == \"" + serviceName + "\" and .role == \"" + role + "\" and .principal == \"" + principal + "\""+includeInactives+").id");
                JsonNode in = MAPPER.readTree(new String(response.body().bytes()));
                List<JsonNode> json = q.apply(in);

                if (json.size()>0) {
                    frameworkId = Optional.of(json.stream()
                            .map(fwId -> fwId.toString().replace("\"", ""))
                            .toArray(String[]::new)
                    );
                } else if (json.size()==0) {
                    LOG.error("No frameworks found for (" + serviceName + "," + role + "," + principal + ")");
                } else {
                    LOG.error("Several frameworks found for the same (" + serviceName + "," + role + "," + principal + ")");
                }
            } else {
                LOG.info("Error finding framework ("+serviceName+","+role+","+principal+"): " + response
                        .code() + " and message: " + response.errorBody());
            }
        } catch (IOException e) {
            LOG.info("Unregister failure with message " + e.getMessage());
        } finally {
            return frameworkId;
        }
    }

    /**
     * Returns the list of mesos slaves where the specified framework is found
     * @param frameworkId framework to locate inside the mesos slaves
     * @return Optional list of slaveIds
     */
    public Optional<String[]> findSlavesForFramework(String frameworkId) {
        Call<ResponseBody> mesosCall;
        Optional<String[]> slaveIds = Optional.empty();

        try {
            if (!hasEndpointPrefix()) mesosCall = mesosInterface.findFrameworks();
            else mesosCall = mesosInterface.findFrameworks(getEndpointsPrefix());

            Response<ResponseBody> response = mesosCall.execute();
            LOG.info("findSlavesForFramework " + response.message());
            if (response.code() == HTTPUtils.HTTP_OK_CODE) {
                JsonQuery q = JsonQuery.compile(".frameworks[]|select(.id==\""+frameworkId+"\").tasks[].slave_id");
                JsonNode in = MAPPER.readTree(new String(response.body().bytes()));
                List<JsonNode> slaves = q.apply(in);

                // might be a completed framework
                if (slaves.isEmpty()) {
                    q = JsonQuery.compile(".completed_frameworks[]|select(.id==\""+frameworkId+"\").completed_tasks[].slave_id");
                    slaves = q.apply(in);
                }

                slaveIds = Optional.of(slaves.stream()
                        .map(slave->slave.toString().replace("\"", ""))
                        .toArray(String[]::new));
            } else {
                LOG.info("Error finding slaves for framework ("+frameworkId+") returned "+response.code()+" - " + response.errorBody());
            }
        } catch (IOException e) {
            LOG.info("Unregister failure with message " + e.getMessage());
        } finally {
            return slaveIds;
        }
    }

}