package org.jivesoftware.openfire.plugin.rest.service;

import javax.annotation.PostConstruct;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jivesoftware.openfire.plugin.rest.exceptions.ServiceException;
import org.jivesoftware.openfire.plugin.rest.exceptions.ExceptionType;
import org.jivesoftware.openfire.plugin.rest.entity.AssistEntity;
import org.jivesoftware.openfire.plugin.rest.entity.AskQueue;

import org.jivesoftware.smack.OpenfireConnection;

import net.sf.json.*;

@Path("restapi/v1/ask")
public class AskService {

    @PostConstruct
    public void init()
    {

    }

/*
    {
        "userID": "deleo",
        "question": "hey jude",
        "emailAddress": "deleo",
        "workgroup": "demo"
    }
*/

    @POST
    @Path("/")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public AssistEntity requestAssistance(AssistEntity assistance) throws ServiceException
    {
        try {
            String response = OpenfireConnection.requestAssistance(assistance);

            if (response != null)
            {
                throw new ServiceException(response, response, ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return assistance;
    }

    @GET
    @Path("/{userId}")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public AskQueue queryAssistance(@PathParam("userId") String userId) throws ServiceException
    {
        try {
            AskQueue queue = OpenfireConnection.queryAssistance(userId);

            if (queue == null)
            {
                throw new ServiceException("Error", "Ask workgroup is inaccesible", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
            return queue;

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
    }

    @POST
    @Path("/{userId}")
    public Response joinAssistChat(@PathParam("userId") String userId) throws ServiceException
    {
        try {
            boolean resp = OpenfireConnection.joinAssistChat(userId);

            if (resp == false)
            {
                throw new ServiceException("Error", "Ask workgroup is inaccesible", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.OK).build();
    }

    @PUT
    @Path("/{userId}")
    public Response sendAssistMessage(@PathParam("userId") String userId, String body) throws ServiceException
    {
        try {
            boolean resp = OpenfireConnection.sendAssistMessage(userId, body);

            if (resp == false)
            {
                throw new ServiceException("Error", "Ask workgroup is inaccesible", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.OK).build();
    }

    @DELETE
    @Path("/{userId}")
    public Response revokeAssistance(@PathParam("userId") String userId) throws ServiceException
    {
        try {
            String response = OpenfireConnection.revokeAssistance(userId);

            if (response != null)
            {
                throw new ServiceException(response, response, ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }
}
