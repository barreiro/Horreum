package io.hyperfoil.tools.horreum.api.internal.services;

import java.util.List;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import io.hyperfoil.tools.horreum.api.data.View;

@Path("/api/ui")
@Consumes({ MediaType.APPLICATION_JSON })
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "ui", description = "Manage schemas")
public interface UIService {

    @POST
    @Path("view")
    View updateView(@RequestBody(required = true) View view);

    @POST
    @Path("views")
    void createViews(@RequestBody(required = true) List<View> views);

    @DELETE
    @Path("{testId}/view/{viewId}")
    void deleteView(@PathParam("testId") int testId, @PathParam("viewId") int viewId);

    @GET
    @Path("{testId}/views")
    List<View> getViews(@PathParam("testId") int testId);
}
