package org.ifsoft.meet;

import java.io.*;
import java.net.*;
import java.util.*;

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

import org.jivesoftware.openfire.plugin.rest.controller.UserServiceController;
import org.jivesoftware.openfire.plugin.rest.entity.UserEntities;
import org.jivesoftware.openfire.plugin.rest.entity.UserEntity;

import org.jivesoftware.openfire.plugin.rest.exceptions.ServiceException;
import org.jivesoftware.openfire.plugin.rest.exceptions.ExceptionType;
import org.jivesoftware.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Path("restapi/v1/meet")
public class MeetService {

    private static final Logger Log = LoggerFactory.getLogger(MeetService.class);
    private MeetController meetController;

    @PostConstruct
    public void init()
    {
        meetController = MeetController.getInstance();
    }

    //-------------------------------------------------------
    //
    //  Web Push
    //
    //-------------------------------------------------------

    @GET
    @Path("/webpush")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public UserEntities getPushSubscribers()  throws ServiceException
    {
        UserEntities userEntities = UserServiceController.getInstance().getUserEntitiesByProperty("webpush.subscribe.%", null);
        Map<String, UserEntity> users = new HashMap<String, UserEntity>();

        for (UserEntity user : userEntities.getUsers()) {
            user.setProperties(null);
            users.put(user.getUsername(), user);
        }

        return new UserEntities(users.values());
    }

    @GET
    @Path("/webpush/{username}")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public PublicKey getWebPushPublicKey(@PathParam("username") String username) throws ServiceException {
        Log.debug("getWebPushPublicKey " + username);

        String publicKey = JiveGlobals.getProperty("vapid.public.key", null);

        if (publicKey == null)
        {
            publicKey = meetController.getWebPushPublicKey(username);
        }

        if (publicKey == null)
            throw new ServiceException("Exception", "public key not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION,  Response.Status.NOT_FOUND);

        return new PublicKey(publicKey);
    }

    @PUT
    @Path("/webpush/{username}/{resource}")
    public Response putWebPushSubscription(@PathParam("username") String username, @PathParam("resource") String resource, String subscription) throws ServiceException {
        Log.debug("putWebPushSubscription " + username + " " + resource + "\n" + subscription);

        try {
            if (meetController.putWebPushSubscription(username, resource, subscription))
            {
                return Response.status(Response.Status.OK).build();
            }

        } catch (Exception e) {
            Log.error("putWebPushSubscription", e);
        }
        return Response.status(Response.Status.BAD_REQUEST).build();
    }

    @POST
    @Path("/webpush/{username}")
    public Response postWebPush(@PathParam("username") String username, String notification) throws ServiceException {
        Log.debug("postWebPush " + username + "\n" + notification);

        try {
            if (meetController.postWebPush(username, notification))
            {
                return Response.status(Response.Status.OK).build();
            }

        } catch (Exception e) {
            Log.error("postWebPush", e);
        }
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
