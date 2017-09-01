/**
 *
 * Copyright 2010 Jive Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.smack;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

import javax.net.ssl.*;
import javax.security.auth.callback.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response.Status;

import java.security.cert.Certificate;

import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.roster.*;
import org.jivesoftware.smack.roster.packet.*;
import org.jivesoftware.smack.chat.*;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.filter.*;
import org.jivesoftware.smack.provider.*;
import org.jivesoftware.smack.util.*;

import org.jivesoftware.smackx.muc.*;
import org.jivesoftware.smackx.muc.packet.*;
import org.jivesoftware.smackx.chatstates.*;
import org.jivesoftware.smackx.*;

import org.jxmpp.jid.*;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Resourcepart;
import org.jxmpp.stringprep.XmppStringprepException;

import org.jivesoftware.openfire.*;
import org.jivesoftware.openfire.session.LocalClientSession;
import org.jivesoftware.openfire.net.VirtualConnection;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.auth.AuthToken;
import org.jivesoftware.openfire.auth.AuthFactory;
import org.jivesoftware.openfire.plugin.rest.*;
import org.jivesoftware.openfire.plugin.rest.entity.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.xmpp.packet.JID;
import org.dom4j.*;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.servlets.EventSource;
import org.eclipse.jetty.servlets.EventSourceServlet;

import org.ifsoft.meet.MeetController;

/**
 * A virtual implementation of {@link XMPPConnection}, intended to be used in
 * server side client session.
 *
 * Packets that should be processed by the client to simulate a received stanza
 * can be delivered using the {@linkplain #processStanza(Stanza)} method.
 * It invokes the registered stanza(/packet) interceptors and listeners.
 *
 * @see XMPPConnection
 * @author Guenther Niess
 */
public class OpenfireConnection extends AbstractXMPPConnection implements ChatMessageListener, ChatManagerListener, StanzaListener, RosterListener, InvitationListener, InvitationRejectionListener {
    private static Logger Log = LoggerFactory.getLogger( "OpenfireConnection" );

    private static final ConcurrentHashMap<String, OpenfireConnection> connections = new ConcurrentHashMap<String, OpenfireConnection>();
    private static final ConcurrentHashMap<String, OpenfireConnection> users = new ConcurrentHashMap<String, OpenfireConnection>();

    private boolean reconnect = false;
    private LocalClientSession session;
    private SmackConnection smackConnection;
    private ServletHolder sseHolder;
    private ClientServlet clientServlet;
    private String ssePath;

    public ConcurrentHashMap<String, Chat> chats;
    public ConcurrentHashMap<String, MultiUserChat> groupchats;

    public ChatManager chatManager;
    public MultiUserChatManager mucManager;
    public Roster roster;
    public OpenfireConfiguration config;
    public boolean autoStarted = false;


    // -------------------------------------------------------
    //
    // Statics
    //
    // -------------------------------------------------------

    public static OpenfireConnection createConnection(String username, String password)
    {
        try {
            AuthFactory.authenticate( username, password );

        } catch ( Exception e ) {
            return null;
        }

        OpenfireConnection connection = users.get(username);

        if (connection == null)
        {
            try {
                OpenfireConfiguration config = OpenfireConfiguration.builder()
                  .setUsernameAndPassword(username, password)
                  .setXmppDomain(XMPPServer.getInstance().getServerInfo().getXMPPDomain())
                  .setResource("ofchat" + new Random(new Date().getTime()).nextInt())
                  .setHost(XMPPServer.getInstance().getServerInfo().getHostname())
                  .setPort(0)
                  .build();

                connection = new OpenfireConnection(config);
                connection.connect();
                connection.login();
                connection.addPacketListener(connection, new PacketTypeFilter(Message.class));
                connections.put(connection.getStreamId(), connection);

                users.put(username, connection);

                connection.chatManager = ChatManager.getInstanceFor(connection);
                connection.chatManager.addChatListener(connection);
                connection.chats = new ConcurrentHashMap<String, Chat>();

                connection.mucManager = MultiUserChatManager.getInstanceFor(connection);
                connection.mucManager.addInvitationListener(connection);

                connection.roster = Roster.getInstanceFor(connection);
                connection.roster.addRosterListener(connection);


                connection.groupchats = new ConcurrentHashMap<String, MultiUserChat>();

            } catch (Exception e) {
                Log.error("createConnection", e);
            }
        }

        return connection;
    }

    public static OpenfireConnection getConnection(String streamId)
    {
        return connections.get(streamId);
    }

    public static OpenfireConnection removeConnection(String streamId) throws SmackException
    {
        OpenfireConnection connection = connections.remove(streamId);

        if (connection != null)
        {
            users.remove(connection.getUsername());
            connection.removePacketListener(connection);
            connection.disconnect(new Presence(Presence.Type.unavailable));
        }

        return connection;
    }

    public static RosterEntities getRosterEntities(String streamId) {
        Log.debug("getRoster " + streamId);

        List<RosterItemEntity> rosterEntities = new ArrayList<RosterItemEntity>();

        OpenfireConnection connection = connections.get(streamId);

        if (connection != null)
        {
            try {
                Collection<RosterEntry> entries = connection.roster.getEntries();

                for (RosterEntry entry : entries) {
                    Presence presence = connection.roster.getPresence(JidCreate.entityBareFrom(entry.getUser()));

                    int entryStatus = 0;

                    if (entry.getType() != null) {
                        if (entry.getType().equals(RosterPacket.ItemType.both))
                            entryStatus = 3;
                        if (entry.getType().equals(RosterPacket.ItemType.from))
                            entryStatus = 2;
                        if (entry.getType().equals(RosterPacket.ItemType.none))
                            entryStatus = 0;
                        if (entry.getType().equals(RosterPacket.ItemType.remove))
                            entryStatus = -1;
                        if (entry.getType().equals(RosterPacket.ItemType.to))
                            entryStatus = 1;
                    }

                    RosterItemEntity rosterItemEntity = new RosterItemEntity(entry.getUser(), entry.getName(), entryStatus);

                    List<String> groups = new ArrayList<String>();

                    for (RosterGroup group : entry.getGroups()) {
                        groups.add(group.getName());
                    }

                    rosterItemEntity.setGroups(groups);

                    String show = presence.getType().name();

                    if (presence.getMode() != null)
                        show = presence.getMode().toString();

                    rosterItemEntity.setStatus(presence.getStatus());
                    rosterItemEntity.setShow(show);
                    rosterEntities.add(rosterItemEntity);

                    Log.debug("Roster entry " + entry.getUser() + " " + entry.getName() + " "
                            + presence.getType().name() + " " + presence.getMode() + " " + presence.getStatus());
                }

            } catch (Exception e) {
                Log.error("getRoster", e);
                return null;
            }
        }

        return new RosterEntities(rosterEntities);
    }


    // -------------------------------------------------------
    //
    // OpenfireConnection
    //
    // -------------------------------------------------------


    public OpenfireConnection(OpenfireConfiguration configuration) {
        super(configuration);

        config = configuration;
        user = getUserJid();
    }

    public String getSsePath()
    {
        return ssePath;
    }

    @Override
    protected void connectInternal() {
        Log.debug("connectInternal " + config.getUsername());

        streamId = "ofchat" + new Random(new Date().getTime()).nextInt();
        smackConnection = new SmackConnection(streamId, this);

        if (reconnect) {
            notifyReconnection();
        }

        clientServlet = new ClientServlet();
        sseHolder = new ServletHolder(clientServlet);
        sseHolder.setAsyncSupported(true);
        ssePath = "/" + config.getUsername();

        RESTServicePlugin.getInstance().addServlet(sseHolder, ssePath);

        connected = true;
        saslFeatureReceived.reportSuccess();
        tlsHandled.reportSuccess();
    }

    @Override
    protected void shutdown() {
        Log.info("shutdown " + config.getUsername());

        user = null;
        authenticated = false;
        reconnect = true;

        try {
            JID userJid = XMPPServer.getInstance().createJID(getUsername(), config.getResource().toString());

            session = (LocalClientSession) SessionManager.getInstance().getSession(userJid);

            if (session != null)
            {
                session.close();
                SessionManager.getInstance().removeSession(session);
            }

            RESTServicePlugin.getInstance().removeServlets(sseHolder);

        } catch (Exception e) {
            Log.error("shutdown", e);
        }
    }

    @Override
    public boolean isSecureConnection() {
        return false;
    }

    @Override
    public boolean isUsingCompression() {
        return false;
    }

    @Override
    protected void loginInternal(String username, String password, Resourcepart resource) throws XMPPException
    {
        try {
            username = username.toLowerCase().trim();
            user = getUserJid();
            JID userJid = XMPPServer.getInstance().createJID(username, resource.toString());

            session = (LocalClientSession) SessionManager.getInstance().getSession(userJid);

            if (session != null)
            {
                session.close();
                SessionManager.getInstance().removeSession(session);
            }

            AuthToken authToken = null;

            try {
                authToken = AuthFactory.authenticate( username, password );

            } catch ( UnauthorizedException e ) {
                authToken = new AuthToken(resource.toString(), true);
            }

            session = SessionManager.getInstance().createClientSession( smackConnection, (Locale) null );
            smackConnection.setRouter( new SessionPacketRouter( session ) );
            session.setAuthToken(authToken, resource.toString());
            authenticated = true;

            afterSuccessfulLogin(false);

        } catch (Exception e) {
            Log.error("XMPPConnection login error", e);
        }
    }

    private void sendPacket(TopLevelStreamElement stanza)
    {
        sendPacket(stanza.toXML().toString());
        firePacketSendingListeners((Stanza) stanza);
    }

    public void sendPacket(String data)
    {
        try {
            Log.debug("sendPacket " + data );
            smackConnection.getRouter().route(DocumentHelper.parseText(data).getRootElement());

        } catch ( Exception e ) {
            Log.error( "An error occurred while attempting to route the packet : ", e );
        }
    }

    @Override
    public void sendNonza(Nonza element) {
        TopLevelStreamElement stanza = (TopLevelStreamElement) element;
        sendPacket(stanza);
    }

    @Override
    protected void sendStanzaInternal(Stanza packet) {
        TopLevelStreamElement stanza = (TopLevelStreamElement) packet;
        sendPacket(stanza);
    }

    public void enableStreamFeature(ExtensionElement streamFeature) {
        addStreamFeature(streamFeature);
    }

    public boolean postMessage(String to, String body) {
        Log.debug("postMessage " + to + " " + body);

        try {
            Message message = new Message(to, body);
            sendStanza(message);
            return true;

        } catch (Exception e) {
            Log.error("postMessage", e);
            return false;
        }
    }

    public boolean postPresence(String show, String status) {
        Log.debug("postPresence " + show + " " + status);

        try {
            Presence p = new Presence(Presence.Type.available);

            if ("offline".equals(show)) {
                p = new Presence(Presence.Type.unavailable);
            } else if ("available".equals(show)) {
                p = new Presence(Presence.Type.available);
                p.setMode(Presence.Mode.available);
            } else if ("away".equals(show)) {
                p = new Presence(Presence.Type.available);
                p.setMode(Presence.Mode.away);
            } else if ("chat".equals(show)) {
                p = new Presence(Presence.Type.available);
                p.setMode(Presence.Mode.chat);
            } else if ("dnd".equals(show)) {
                p = new Presence(Presence.Type.available);
                p.setMode(Presence.Mode.dnd);
            } else if ("xa".equals(show)) {
                p = new Presence(Presence.Type.available);
                p.setMode(Presence.Mode.xa);
            }

            if (status != null) p.setStatus(status);
            sendPacket(p);
            return true;

        } catch (Exception e) {
            Log.error("setPresence", e);
            return false;
        }
    }

    @Override
    public void chatCreated(final Chat chat, final boolean createdLocally)
    {
        String participant = chat.getParticipant().toString();

        Log.debug("Chat created: " + participant);

        if (chats.containsKey(participant) == false)
        {
            chats.put(participant, chat);
        }

        chat.addMessageListener(this);
    }

    @Override
    public void processMessage(Chat chat, Message message)
    {
        Log.debug("Received chat message: " + message.getBody());

        if (message.getType() == Message.Type.chat)
        {
            if (message.getBody() != null)
            {
                clientServlet.broadcast("chatapi.chat", "{\"type\": \"" + message.getType() + "\", \"to\":\"" + message.getTo() + "\", \"from\":\"" + message.getFrom() + "\", \"body\": \"" + message.getBody() + "\"}");
            } else {

                ExtensionElement element = message.getExtension("http://jabber.org/protocol/chatstates");

                if (element != null)
                {
                    clientServlet.broadcast("chatapi.chat", "{\"type\": \"" + message.getType() + "\", \"to\":\"" + message.getTo() + "\", \"from\":\"" + message.getFrom() + "\", \"state\": \"" + element.getElementName() + "\"}");
                }
            }
        }
    }

    public boolean setCurrentState(String state, String to) {
        Log.debug("setCurrentState " + to + "\n" + state);

        try {
            Chat chat = chats.get(to);

            if (chat == null) {
                chat = chatManager.createChat(JidCreate.entityBareFrom(to), null);
                chats.put(to, chat);
            }

            ChatStateManager chatStateManager = ChatStateManager.getInstance(this);

            if ("composing".equals(state))  chatStateManager.setCurrentState(ChatState.composing, chat);
            if ("paused".equals(state))     chatStateManager.setCurrentState(ChatState.paused, chat);
            if ("active".equals(state))     chatStateManager.setCurrentState(ChatState.active, chat);
            if ("inactive".equals(state))   chatStateManager.setCurrentState(ChatState.inactive, chat);
            if ("gone".equals(state))       chatStateManager.setCurrentState(ChatState.gone, chat);

            return true;

        } catch (Exception e) {
            Log.error("setCurrentState", e);
            return false;
        }
    }

    public boolean sendChatMessage(String message, String to) {
        Log.debug("sendChatMessage " + to + "\n" + message);

        try {
            Chat chat = chats.get(to);

            if (chat == null) {
                chat = chatManager.createChat(JidCreate.entityBareFrom(to), null);
                chats.put(to, chat);
            }

            chat.sendMessage(message);
            return true;

        } catch (Exception e) {
            Log.error("sendChatMessage", e);
            return false;
        }
    }

    // -------------------------------------------------------
    //
    // StanzaListener
    //
    // -------------------------------------------------------

    public void processStanza(Stanza packet)
    {
        Log.debug("Received packet: \n" + packet.toXML());

        Message message = (Message) packet;

        if (message.getType() == Message.Type.groupchat)
        {
            clientServlet.broadcast("chatapi.muc", "{\"type\": \"" + message.getType() + "\", \"to\":\"" + message.getTo() + "\", \"from\":\"" + message.getFrom() + "\", \"body\": \"" + message.getBody() + "\"}");

            if (autoStarted)
            {
                MeetController.getInstance().postWebPush(getUsername(), "{\"title\":\"" + message.getFrom() + "\", \"message\": \"" + message.getBody() + "\"}");
            }
        }
        else {

            GroupChatInvitation invitation = (GroupChatInvitation)packet.getExtension(GroupChatInvitation.ELEMENT, GroupChatInvitation.NAMESPACE);

            if (invitation != null)
            {
                try {
                    String room = invitation.getRoomAddress();
                    String url = JiveGlobals.getProperty("ofmeet.root.url.secure", "https://" + XMPPServer.getInstance().getServerInfo().getHostname() + ":" + JiveGlobals.getProperty("httpbind.port.secure", "7443")) + "/meet/" + room.split("@")[0];
                    clientServlet.broadcast("chatapi.muc", "{\"type\": \"invitationReceived\", \"room\":\"" + room + "\", \"inviter\":\"" + message.getFrom() + "\", \"to\":\"" + message.getTo() + "\", \"from\":\"" + message.getFrom() + "\", \"url\":\"" + url + "\", \"reason\": \"" + message.getBody() + "\"}");

                } catch (Exception e) {
                    Log.error("invitationReceived", e);
                }
            }
        }
    }


    @Override
    public void entriesAdded(Collection<Jid> addresses) {}

    @Override
    public void entriesDeleted(Collection<Jid> addresses) {}

    @Override
    public void entriesUpdated(Collection<Jid> addresses) {}

    @Override
    public void presenceChanged(Presence presence)
    {
        clientServlet.broadcast("chatapi.presence", "{\"type\": \"presence\", \"to\":\"" + presence.getTo() + "\", \"from\":\"" + presence.getFrom() + "\", \"status\":\"" + presence.getStatus() + "\", \"show\": \"" + presence.getMode() + "\"}");
    }

    // -------------------------------------------------------
    //
    // InvitationListener
    //
    // -------------------------------------------------------

    @Override
    public void invitationReceived(XMPPConnection xmppConnection, MultiUserChat multiUserChat, EntityJid inviter, String reason, String password, Message message, MUCUser.Invite invitation)
    {
        try {
            String room = multiUserChat.getRoom().toString();
            String url = JiveGlobals.getProperty("ofmeet.root.url.secure", "https://" + XMPPServer.getInstance().getServerInfo().getHostname() + ":" + JiveGlobals.getProperty("httpbind.port.secure", "7443")) + "/meet/" + room.split("@")[0];
            clientServlet.broadcast("chatapi.muc", "{\"type\": \"invitationReceived\", \"password\":\"" + password + "\", \"room\":\"" + room + "\", \"inviter\":\"" + inviter + "\", \"to\":\"" + message.getTo() + "\", \"from\":\"" + message.getFrom() + "\", \"url\":\"" + url + "\", \"reason\": \"" + reason + "\"}");

        } catch (Exception e) {
            Log.error("invitationReceived", e);
        }
    }

    @Override
    public void invitationDeclined(EntityBareJid jid, String reason, Message message, MUCUser.Decline decline) {
        Log.debug("invitationDeclined " + jid);
    }

    // -------------------------------------------------------
    //
    // Groupchat/ Chat rooms
    //
    // -------------------------------------------------------

    public boolean joinRoom(String mGroupChatName, String mNickName) {
        Log.debug("joinRoom " + mGroupChatName + " " + mNickName);

        try {
            MultiUserChat mMultiUserChat = groupchats.get(mGroupChatName);

            if (mMultiUserChat == null)
            {
                mMultiUserChat = mucManager.getMultiUserChat(JidCreate.entityBareFrom(mGroupChatName));
                mMultiUserChat.addInvitationRejectionListener(this);
                groupchats.put(mGroupChatName, mMultiUserChat);
            }

            mMultiUserChat.join(Resourcepart.from(mNickName));
            return true;

        } catch (Exception e) {
            Log.error("joinRoom", e);
            return false;
        }
    }

    public boolean leaveRoom(String mGroupChatName) {
        Log.debug("leaveRoom " + mGroupChatName);

        try {
            MultiUserChat mMultiUserChat = groupchats.get(mGroupChatName);
            mMultiUserChat.leave();
            return true;

        } catch (Exception e) {
            Log.error("leaveRoom", e);
            return false;
        }
    }

    public boolean sendRoomMessage(String mGroupChatName, String text) {
        Log.debug("sendRoomMessage " + mGroupChatName + "\n" + text);

        try {
            groupchats.get(mGroupChatName).sendMessage(text);
            return true;

        } catch (Exception e) {
            Log.error("sendRoomMessage", e);
            return false;
        }
    }

    public boolean inviteToRoom(String mGroupChatName, String inviteJid, String reason) {
        Log.debug("inviteToRoom " + mGroupChatName + " " + inviteJid + "\n" + reason);

        try {
            groupchats.get(mGroupChatName).invite(JidCreate.entityBareFrom(inviteJid), reason);
            return true;

        } catch (Exception e) {
            Log.error("inviteToRoom", e);
            return false;
        }
    }

    // -------------------------------------------------------
    //
    // Common
    //
    // -------------------------------------------------------


    private EntityFullJid getUserJid()
    {
        try {
            return JidCreate.entityFullFrom(config.getUsername() + "@" + config.getXMPPServiceDomain() + "/" + config.getResource());
        }
        catch (XmppStringprepException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getUsername()
    {
        return config.getUsername().toString();
    }

    public void handleParser(XmlPullParser parser)
    {
        Stanza stanza = null;

        try {
            stanza = PacketParserUtils.parseStanza(parser);
        }
        catch (Exception e) {
            Log.error("handleParser", e);
        }

        if (stanza != null) {
            invokeStanzaCollectorsAndNotifyRecvListeners(stanza);
        }
    }

    // -------------------------------------------------------
    //
    // SmackConnection
    //
    // -------------------------------------------------------

    public class SmackConnection extends VirtualConnection
    {
        private SessionPacketRouter router;
        private String remoteAddr;
        private String hostName;
        private LocalClientSession session;
        private boolean isSecure = false;
        private OpenfireConnection connection;

        public SmackConnection(String hostName, OpenfireConnection connection)
        {
            this.remoteAddr = hostName;
            this.hostName = hostName;
            this.connection = connection;
        }

        public void setConnection(OpenfireConnection connection) {
            this.connection = connection;
        }

        public boolean isSecure() {
            return isSecure;
        }

        public void setSecure(boolean isSecure) {
            this.isSecure = isSecure;
        }

        public SessionPacketRouter getRouter()
        {
            return router;
        }

        public void setRouter(SessionPacketRouter router)
        {
            this.router = router;
        }

        public void closeVirtualConnection()
        {
            Log.info("SmackConnection - close ");

            if (this.connection!= null) this.connection.shutdown();
        }

        public byte[] getAddress() {
            return remoteAddr.getBytes();
        }

        public String getHostAddress() {
            return remoteAddr;
        }

        public String getHostName()  {
            return ( hostName != null ) ? hostName : "0.0.0.0";
        }

        public void systemShutdown() {

        }

        public void deliver(org.xmpp.packet.Packet packet) throws UnauthorizedException
        {
            deliverRawText(packet.toXML());
        }

        public void deliverRawText(String text)
        {
            Log.debug("SmackConnection - deliverRawText\n" + text);

            if (clientServlet != null)
            {
                clientServlet.broadcast("chatapi.xmpp", text);
            }

            try {
                StringReader stringReader = new StringReader(text);

                final XmlPullParser parser = XmlPullParserFactory.newInstance().newPullParser();
                parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
                parser.setInput(stringReader);

                int eventType = parser.getEventType();

                do {
                    eventType = parser.next();

                    if (eventType == XmlPullParser.START_TAG)
                    {
                        connection.handleParser(parser);
                    }

                    else if (eventType == XmlPullParser.END_TAG) {

                    }
                } while (eventType != XmlPullParser.END_DOCUMENT);
            }

            catch (Exception e) {
                Log.error("deliverRawText error", e);
            }
        }

        @Override
        public org.jivesoftware.openfire.spi.ConnectionConfiguration getConfiguration()
        {
            // TODO Here we run into an issue with the ConnectionConfiguration introduced in Openfire 4:
            //      it is not extensible in the sense that unforeseen connection types can be added.
            //      For now, null is returned, as this object is likely to be unused (its lifecycle is
            //      not managed by a ConnectionListener instance).
            return null;
        }

        public Certificate[] getPeerCertificates() {
            return null;
        }

    }

    // -------------------------------------------------------
    //
    // ClientServlet
    //
    // -------------------------------------------------------

    public class ClientServlet extends EventSourceServlet
    {
        private ClientEventSource clientEventSource = null;

        public void broadcast(String name, String event)
        {
            if (clientEventSource != null)
            {
                for (EventSource.Emitter emitter : clientEventSource.emitters)
                {
                    try
                    {
                        emitter.event(name, event);
                    }
                    catch (IOException e)
                    {
                        Log.error("could not send update to client", e);
                    }
                }
            }
        }

        @Override
        public void init() throws ServletException
        {
            super.init();
        }

        @Override
        public void destroy()
        {
            if (clientEventSource != null) clientEventSource.emitters.clear();
            super.destroy();
        }

        @Override
        protected EventSource newEventSource(HttpServletRequest request)
        {
            String username = request.getUserPrincipal().getName();

            Log.debug("newEventSource " + username);

            if (username == null || username.equals(getUsername()) == false) return null;

            clientEventSource = new ClientEventSource();
            return clientEventSource;
        }

        final class ClientEventSource implements EventSource
        {
            private Set<EventSource.Emitter> emitters = new CopyOnWriteArraySet<>();
            private Emitter emitter;
            private volatile boolean closed = false;
            private ClientServlet servlet;

            @Override
            public void onOpen(Emitter emitter) throws IOException
            {
                this.emitter = emitter;
                emitters.add(emitter);
            }

            @Override
            public void onClose()
            {
                emitters.remove(this.emitter);

            }
        }

    }

    // -------------------------------------------------------
    //
    // OpenfireConfiguration
    //
    // -------------------------------------------------------

    public static class OpenfireConfiguration extends ConnectionConfiguration
    {
        protected OpenfireConfiguration(Builder builder) {
            super(builder);
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder extends ConnectionConfiguration.Builder<Builder, OpenfireConfiguration> {

            private Builder() {
            }

            @Override
            public OpenfireConfiguration build() {
                return new OpenfireConfiguration(this);
            }

            @Override
            protected Builder getThis() {
                return this;
            }
        }
    }
}