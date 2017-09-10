package org.jivesoftware.openfire.plugin.rest.service;

import java.io.*;
import java.util.*;
import java.text.*;

import javax.servlet.http.HttpServletRequest;
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
import javax.ws.rs.core.Context;

import java.security.Principal;

import javax.xml.bind.*;
import org.codehaus.jackson.map.*;
import org.codehaus.jackson.xc.*;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.util.*;

import org.jivesoftware.openfire.plugin.rest.controller.UserServiceController;
import org.jivesoftware.openfire.plugin.rest.controller.MUCRoomController;

import org.jivesoftware.openfire.plugin.rest.exceptions.ServiceException;
import org.jivesoftware.openfire.plugin.rest.exceptions.ExceptionType;

import org.jivesoftware.openfire.plugin.rest.*;

import org.jivesoftware.openfire.plugin.rest.entity.RosterEntities;
import org.jivesoftware.openfire.plugin.rest.entity.RosterItemEntity;
import org.jivesoftware.openfire.plugin.rest.entity.UserEntities;
import org.jivesoftware.openfire.plugin.rest.entity.MUCChannelType;
import org.jivesoftware.openfire.plugin.rest.entity.MUCRoomEntities;
import org.jivesoftware.openfire.plugin.rest.entity.MUCRoomEntity;
import org.jivesoftware.openfire.plugin.rest.entity.OccupantEntities;
import org.jivesoftware.openfire.plugin.rest.entity.ParticipantEntities;
import org.jivesoftware.openfire.plugin.rest.entity.WorkgroupEntities;
import org.jivesoftware.openfire.plugin.rest.entity.AssistQueues;

import org.jivesoftware.openfire.user.*;
import org.jivesoftware.openfire.SharedGroupException;
import org.jivesoftware.openfire.user.UserNotFoundException;

import org.jivesoftware.openfire.auth.*;
import org.jivesoftware.openfire.sip.sipaccount.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.xmpp.packet.*;
import org.jivesoftware.openfire.archive.*;

import org.jivesoftware.smack.OpenfireConnection;


@Path("restapi/v1/chat")
public class ChatService {

    private static final Logger Log = LoggerFactory.getLogger(ChatService.class);
    private XMPPServer server;
    private UserServiceController userService;

    @Context
    private HttpServletRequest httpRequest;

    @PostConstruct
    public void init()
    {
        server = XMPPServer.getInstance();
        userService = UserServiceController.getInstance();
    }

    //-------------------------------------------------------
    //
    //  login/logoff
    //
    //-------------------------------------------------------

    @POST
    @Path("/{username}/login")
    @Produces(MediaType.TEXT_PLAIN)
    public String login(@PathParam("username") String username, String password) throws ServiceException
    {
        Log.debug("login " + username + "\n" + password);

        try {
            OpenfireConnection connection = OpenfireConnection.createConnection(username, password);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection error", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            return connection.getStreamId();

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
    }

    @POST
    @Path("/{streamid}/logoff")
    public Response logoff(@PathParam("streamid") String streamid) throws ServiceException
    {
        Log.debug("logoff " + streamid);

        try {
            OpenfireConnection connection = OpenfireConnection.removeConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            return Response.status(Response.Status.OK).build();

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
    }


    //-------------------------------------------------------
    //
    //  POST xmpp messags
    //
    //-------------------------------------------------------

    @POST
    @Path("/{streamid}/xmpp")
    public Response postXmppMessage(@PathParam("streamid") String streamid, String xmpp) throws ServiceException
    {
        Log.debug("postXmppMessage " + streamid + "\n" + xmpp);

        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            connection.sendPacket(xmpp);

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    /**
     *      Chat Presence
     */
    //-------------------------------------------------------
    //
    //  POST self presence
    //
    //-------------------------------------------------------

    @POST
    @Path("/{streamid}/presence")
    public Response postPresence(@PathParam("streamid") String streamid, @QueryParam("show") String show, @QueryParam("status") String status) throws ServiceException
    {
        Log.debug("postPresence " + show + " " + status);

        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            connection.postPresence(show, status);

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    //-------------------------------------------------------
    //
    //  POST chat message or chat-state and GET chat history
    //
    //-------------------------------------------------------

    @POST
    @Path("/{streamid}/messages/{to}")
    public Response postMessage(@PathParam("streamid") String streamid, @PathParam("to") String to, String body) throws ServiceException
    {
        Log.debug("postMessage " + to + "\n" + body);

        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            connection.sendChatMessage(body, to);

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @POST
    @Path("/{streamid}/chatstate/{state}/{to}")
    public Response postChatState(@PathParam("streamid") String streamid, @PathParam("state") String state, @PathParam("to") String to) throws ServiceException
    {
        Log.debug("postChatState " + to + "\n" + state);

        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            connection.setCurrentState(state, to);

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @GET
    @Path("/{streamid}/messages")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public Conversations getConversations(@PathParam("streamid") String streamid, @QueryParam("keywords") String keywords, @QueryParam("to") String to, @QueryParam("start") String start, @QueryParam("end") String end, @QueryParam("room") String room, @QueryParam("service") String service) throws ServiceException
    {
        Log.debug("getConversations " + streamid + " " + keywords + " " + " " + to  + " " + start + " " + end + " " + room + " " + service);

        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            ArchiveSearch search = new ArchiveSearch();
            JID participant1JID = makeJid(connection.getUsername());
            JID participant2JID = null;

            if (to != null) participant2JID = makeJid(to);

            if (participant2JID != null) {
                search.setParticipants(participant1JID, participant2JID);
            } else  {
                search.setParticipants(participant1JID);
            }

            if (start != null)
            {
                DateFormat formatter = new SimpleDateFormat("MM/dd/yy");
                try {
                    Date date = formatter.parse(start);
                    search.setDateRangeMin(date);
                }
                catch (Exception e) {
                    Log.error("getConversations", e);
                    throw new ServiceException("Exception", "Bad start date", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
                }
            }

            if (end != null)
            {
                DateFormat formatter = new SimpleDateFormat("MM/dd/yy");
                try {
                    Date date = formatter.parse(end);
                    // The user has chosen an end date and expects that any conversation
                    // that falls on that day will be included in the search results. For
                    // example, say the user choose 6/17/2006 as an end date. If a conversation
                    // occurs at 5:33 PM that day, it should be included in the results. In
                    // order to make this possible, we need to make the end date one millisecond
                    // before the next day starts.
                    date = new Date(date.getTime() + JiveConstants.DAY - 1);
                    search.setDateRangeMax(date);
                }
                catch (Exception e) {
                    Log.error("getConversations", e);
                    throw new ServiceException("Exception", "Bad end date", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
                }
            }

            if (keywords != null) search.setQueryString(keywords);

            if (service == null) service = "conference";

            if (room != null)
            {
                search.setRoom(new JID(room + "@" + service + "." + server.getServerInfo().getXMPPDomain()));
            }

            search.setSortOrder(ArchiveSearch.SortOrder.ascending);

            Collection<Conversation> conversations = new ArchiveSearcher().search(search);
            Collection<Conversation> list = new ArrayList<Conversation>();

            for (Conversation conversation : conversations)
            {
                list.add(conversation);
            }

            return new Conversations(list);

        } catch (Exception e) {
            Log.error("getConversations", e);
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
    }
    //-------------------------------------------------------
    //
    //  Search for users. CRUD user profile (properties)
    //
    //-------------------------------------------------------

    @GET
    @Path("/users")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public UserEntities getUser(@QueryParam("search") String search) throws ServiceException
    {
        return userService.getUsersBySearch(search);
    }

    @POST
    @Path("/{streamid}/users/{propertyName}")
    public Response setUserProperty(@PathParam("streamid") String streamid, @PathParam("propertyName") String propertyName, String propertyValue) throws ServiceException
    {
        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            User user = server.getUserManager().getUser(connection.getUsername());
            user.getProperties().put(propertyName, propertyValue);

        } catch (Exception e) {
            Log.error("setUserProperty", e);
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.OK).build();
    }

    @DELETE
    @Path("/{streamid}/users/{propertyName}")
    public Response deleteUserProperty(@PathParam("streamid") String streamid, @PathParam("propertyName") String propertyName) throws ServiceException
    {
        try {
            OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            User user = server.getUserManager().getUser(connection.getUsername());
            user.getProperties().remove(propertyName);

        } catch (Exception e) {
            Log.error("deleteUserProperty", e);
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.OK).build();
    }

    //-------------------------------------------------------
    //
    //  CRUD contacts
    //
    //-------------------------------------------------------

    @GET
    @Path("/{streamid}/contacts")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public RosterEntities getUserRoster(@PathParam("streamid") String streamid) throws ServiceException
    {
        RosterEntities roster = OpenfireConnection.getRosterEntities(streamid);

        if (roster == null)
        {
            throw new ServiceException("Exception", "get roster failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return roster;
    }

    @POST
    @Path("/{streamid}/contacts")
    public Response createRoster(@PathParam("streamid") String streamid, RosterItemEntity rosterItemEntity) throws ServiceException
    {
        Log.debug("createRoster");

        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            userService.addRosterItem(connection.getUsername(), rosterItemEntity);

        } catch (Exception e) {
            Log.error("getConversations", e);
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.CREATED).build();
    }

    @PUT
    @Path("/{streamid}/contacts/{rosterJid}")
    public Response updateRoster(@PathParam("streamid") String streamid, @PathParam("rosterJid") String rosterJid, RosterItemEntity rosterItemEntity) throws ServiceException
    {
        Log.debug("updateRoster " + rosterJid);

        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
            userService.updateRosterItem(connection.getUsername(), rosterJid, rosterItemEntity);

        } catch (Exception e) {
            Log.error("getConversations", e);
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.CREATED).build();
    }

    @DELETE
    @Path("/{streamid}/contacts/{rosterJid}")
    public Response deleteRoster(@PathParam("streamid") String streamid, @PathParam("rosterJid") String rosterJid) throws ServiceException
    {
        Log.debug("deleteRoster " + rosterJid);

        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
            userService.deleteRosterItem(connection.getUsername(), rosterJid);

        } catch (Exception e) {
            Log.error("getConversations", e);
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
        return Response.status(Response.Status.CREATED).build();
    }


    //-------------------------------------------------------
    //
    //  get, join, leave, post message chat rooms
    //
    //-------------------------------------------------------

    @GET
    @Path("/rooms")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public MUCRoomEntities getMUCRooms(@DefaultValue("conference") @QueryParam("servicename") String serviceName, @DefaultValue(MUCChannelType.PUBLIC) @QueryParam("type") String channelType, @QueryParam("search") String roomSearch, @DefaultValue("false") @QueryParam("expandGroups") Boolean expand)
    {
        return MUCRoomController.getInstance().getChatRooms(serviceName, channelType, roomSearch, expand);
    }

    @GET
    @Path("/rooms/{roomName}")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public MUCRoomEntity getMUCRoomJSON2(@PathParam("roomName") String roomName, @DefaultValue("conference") @QueryParam("servicename") String serviceName, @DefaultValue("false") @QueryParam("expandGroups") Boolean expand) throws ServiceException
    {
        return MUCRoomController.getInstance().getChatRoom(roomName, serviceName, expand);
    }

    @GET
    @Path("/rooms/{roomName}/participants")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public ParticipantEntities getMUCRoomParticipants(@PathParam("roomName") String roomName, @DefaultValue("conference") @QueryParam("servicename") String serviceName)
    {
        return MUCRoomController.getInstance().getRoomParticipants(roomName, serviceName);
    }

    @GET
    @Path("/rooms/{roomName}/occupants")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public OccupantEntities getMUCRoomOccupants(@PathParam("roomName") String roomName, @DefaultValue("conference") @QueryParam("servicename") String serviceName)
    {
        return MUCRoomController.getInstance().getRoomOccupants(roomName, serviceName);
    }

    @PUT
    @Path("/{streamid}/rooms/{roomName}")
    public Response joinRoom(@PathParam("streamid") String streamid, @DefaultValue("conference") @QueryParam("service") String service, @PathParam("roomName") String roomName) throws ServiceException
    {
        Log.debug("joinRoom " + service + " " + roomName);

        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (!connection.joinRoom(roomName + "@" + service + "." + server.getServerInfo().getXMPPDomain(), connection.getUsername()))
            {
                throw new ServiceException("Exception", "join room failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @DELETE
    @Path("/{streamid}/rooms/{roomName}")
    public Response leaveRoom(@PathParam("streamid") String streamid, @DefaultValue("conference") @QueryParam("service") String service, @PathParam("roomName") String roomName) throws ServiceException
    {
        Log.debug("leaveRoom " + service + " " + roomName);

        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (!connection.leaveRoom(roomName + "@" + service + "." + server.getServerInfo().getXMPPDomain()))
            {
                throw new ServiceException("Exception", "join room failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @POST
    @Path("/{streamid}/rooms/{roomName}")
    public Response postToRoom(@PathParam("streamid") String streamid, @DefaultValue("conference") @QueryParam("service") String service, @PathParam("roomName") String roomName, String body) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (!connection.sendRoomMessage(roomName + "@" + service + "." + server.getServerInfo().getXMPPDomain(), body))
            {
                throw new ServiceException("Exception", "join room failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @POST
    @Path("/{streamid}/rooms/{roomName}/{invitedJid}")
    public Response inviteToRoom(@PathParam("streamid") String streamid, @DefaultValue("conference") @QueryParam("service") String service, @PathParam("roomName") String roomName, @PathParam("invitedJid") String invitedJid, String reason) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (!connection.inviteToRoom(roomName + "@" + service + "." + server.getServerInfo().getXMPPDomain(), invitedJid, reason))
            {
                throw new ServiceException("Exception", "join room failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    //-------------------------------------------------------
    //
    //  Assist - Live persoon
    //
    //-------------------------------------------------------

    @GET
    @Path("/{streamid}/assists")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public WorkgroupEntities getWorkgroups(@PathParam("streamid") String streamid) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            String jid = connection.getUsername() + "@" + server.getServerInfo().getXMPPDomain();
            String service = "workgroup." + server.getServerInfo().getXMPPDomain();

            WorkgroupEntities workgroups = connection.getWorkgroups(jid, service);

            if (workgroups == null)
            {
                throw new ServiceException("Exception", "get workgroups failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
            return workgroups;

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
    }

    @GET
    @Path("/{streamid}/assists/{workgroup}")
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public AssistQueues getQueues(@PathParam("streamid") String streamid, @PathParam("workgroup") String workgroup) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (workgroup.indexOf("@") == -1) workgroup = workgroup + "@workgroup." + server.getServerInfo().getXMPPDomain();

            AssistQueues queues = connection.getQueues(workgroup);

            if (queues == null)
            {
                throw new ServiceException("Exception", "get workgroup queues failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }
            return queues;

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }
    }

    @POST
    @Path("/{streamid}/assists/{workgroup}")
    public Response joinWorkgroup(@PathParam("streamid") String streamid, @PathParam("workgroup") String workgroup) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (workgroup.indexOf("@") == -1) workgroup = workgroup + "@workgroup." + server.getServerInfo().getXMPPDomain();

            if (!connection.joinWorkgroup(workgroup))
            {
                throw new ServiceException("Exception", "join workgroup failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @POST
    @Path("/{streamid}/offer/{offerId}")
    public Response acceptOffer(@PathParam("streamid") String streamid, @PathParam("offerId") String offerId) throws ServiceException
    {
        try {

           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (!connection.acceptOffer(offerId))
            {
                throw new ServiceException("Exception", "accept offer failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    @DELETE
    @Path("/{streamid}/offer/{offerId}")
    public Response rejectOffer(@PathParam("streamid") String streamid, @PathParam("offerId") String offerId) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (!connection.rejectOffer(offerId))
            {
                throw new ServiceException("Exception", "reject offer failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }


    @DELETE
    @Path("/{streamid}/assists/{workgroup}")
    public Response leaveWorkgroup(@PathParam("streamid") String streamid, @PathParam("workgroup") String workgroup) throws ServiceException
    {
        try {
           OpenfireConnection connection = OpenfireConnection.getConnection(streamid);

            if (connection == null)
            {
                throw new ServiceException("Exception", "xmpp connection not found", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

            if (workgroup.indexOf("@") == -1) workgroup = workgroup + "@workgroup." + server.getServerInfo().getXMPPDomain();

            if (!connection.leaveWorkgroup(workgroup))
            {
                throw new ServiceException("Exception", "leave workgroup failed", ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
            }

        } catch (Exception e) {
            throw new ServiceException("Exception", e.getMessage(), ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION, Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK).build();
    }

    //-------------------------------------------------------
    //
    //  Utitlities
    //
    //-------------------------------------------------------

    private String getEndUser()
    {
        return null;
    }

    private JID makeJid(String participant1)
    {
        JID participant1JID = null;

        try {
            int position = participant1.lastIndexOf("@");

            if (position > -1) {
                String node = participant1.substring(0, position);
                participant1JID = new JID(JID.escapeNode(node) + participant1.substring(position));
            } else {
                participant1JID = new JID(JID.escapeNode(participant1), server.getServerInfo().getXMPPDomain(), null);
            }
        } catch (Exception e) {
            Log.error("makeJid", e);
        }
        return participant1JID;
    }

    private Object jsonToObject(String json, Class objectClass)
    {
        Object object = null;

        try {
            ObjectMapper mapper = new ObjectMapper();
            AnnotationIntrospector introspector = new JaxbAnnotationIntrospector();
            mapper.setAnnotationIntrospector(introspector);
            object = mapper.readValue(json, objectClass);

        } catch (Exception e) {
            Log.error("jsonToObject", e);
        }

        Log.debug("jsonToObject\n" + json + "\nObject= " + object);
        return object;
    }

    private String objectToJson(Object object)
    {
        String json = null;

        try {
            ObjectMapper mapper = new ObjectMapper();
            AnnotationIntrospector introspector = new JaxbAnnotationIntrospector();
            mapper.setAnnotationIntrospector(introspector);
            json = mapper.writeValueAsString(object);

        } catch (Exception e) {
            Log.error("objectToJson", e);
        }

        Log.debug("objectToJson\n" + json + "\nObject= " + object);
        return json;
    }
}
