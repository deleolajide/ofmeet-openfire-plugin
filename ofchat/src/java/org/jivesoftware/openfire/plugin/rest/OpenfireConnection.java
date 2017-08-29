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

package org.jivesoftware.openfire.plugin.rest;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import javax.security.auth.callback.*;
import java.util.*;
import java.util.concurrent.*;

import java.security.cert.Certificate;

import org.jivesoftware.smack.*;
import org.jivesoftware.openfire.*;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Nonza;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.TopLevelStreamElement;
import org.jivesoftware.smack.util.StringUtils;

import org.jxmpp.jid.EntityFullJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Resourcepart;
import org.jxmpp.stringprep.XmppStringprepException;

import org.jivesoftware.openfire.session.LocalClientSession;
import org.jivesoftware.openfire.net.VirtualConnection;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.auth.AuthToken;
import org.jivesoftware.openfire.auth.AuthFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.xmpp.packet.*;
import org.dom4j.*;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.servlets.EventSource;
import org.eclipse.jetty.servlets.EventSourceServlet;

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
public class OpenfireConnection extends AbstractXMPPConnection {
    private static Logger Log = LoggerFactory.getLogger( "OpenfireConnection" );
    private boolean reconnect = false;
    private LocalClientSession session;
    private SmackConnection smackConnection;
    private ServletHolder sseHolder;

    private EntityFullJid getUserJid() {
        try {
            return JidCreate.entityFullFrom(config.getUsername()
                            + "@"
                            + config.getXMPPServiceDomain()
                            + "/"
                            + (config.getResource() != null ? config.getResource() : "virtual"));
        }
        catch (XmppStringprepException e) {
            throw new IllegalStateException(e);
        }
    }

    public OpenfireConnection(ConnectionConfiguration configuration) {
        super(configuration);
        user = getUserJid();
    }

    @Override
    protected void connectInternal() {
        connected = true;
        saslFeatureReceived.reportSuccess();
        tlsHandled.reportSuccess();
        streamId = "virtual-" + new Random(new Date().getTime()).nextInt();

        smackConnection = new SmackConnection(streamId, this);

        if (reconnect) {
            notifyReconnection();
        }

        sseHolder = new ServletHolder(new ClientServlet());
        sseHolder.setAsyncSupported(true);
        RESTServicePlugin.getInstance().addServlet(sseHolder, "/sse/" + streamId);
    }

    @Override
    protected void shutdown() {
        user = null;
        authenticated = false;
        reconnect = true;

        RESTServicePlugin.getInstance().removeServlets(sseHolder);
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

        } catch (Exception e) {
            Log.error("XMPPConnection login error", e);
        }
    }

    private void sendPacket(TopLevelStreamElement stanza) {
        try {
            String data = stanza.toXML().toString();
            Log.debug("OpenfirePacketWriter sendPacket " + data );
            smackConnection.getRouter().route(DocumentHelper.parseText(data).getRootElement());

            firePacketSendingListeners((Stanza) stanza);

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

    /**
     * Processes a stanza(/packet) through the installed stanza(/packet) collectors and listeners
     * and letting them examine the stanza(/packet) to see if they are a match with the
     * filter.
     *
     * @param packet the stanza(/packet) to process.
     */
    @Override
    public void processStanza(Stanza packet) {
        invokeStanzaCollectorsAndNotifyRecvListeners(packet);
    }

    /**
     * Enable stream feature.
     *
     * @param streamFeature the stream feature.
     * @since 4.2
     */
    public void enableStreamFeature(ExtensionElement streamFeature) {
        addStreamFeature(streamFeature);
    }

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

            try {
                StringReader stringReader = new StringReader(text);

                final XmlPullParser parser = XmlPullParserFactory.newInstance().newPullParser();
                parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
                parser.setInput(stringReader);

                int eventType = parser.getEventType();

                do {
                    if (eventType == XmlPullParser.START_TAG)
                    {
                        connection.parseAndProcessStanza(parser);
                    }

                    else if (eventType == XmlPullParser.END_TAG) {

                    }

                    eventType = parser.next();
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

    public class ClientServlet extends EventSourceServlet
    {
        private final Set<Emitter> emitters = new CopyOnWriteArraySet<>();

        public void broadcast(String event)
        {
            for (Emitter emitter : emitters)
            {
                try
                {
                    emitter.data(event);
                }
                catch (IOException e)
                {
                    Log.error("could not send update to client", e);
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
            this.emitters.clear();
            super.destroy();
        }

        @Override
        protected EventSource newEventSource(HttpServletRequest request)
        {
            return new ClientEventSource();
        }

        final class ClientEventSource implements EventSource {

            private volatile Emitter emitter;
            private volatile boolean closed = false;

            @Override
            public void onOpen(Emitter emitter) throws IOException
            {
                emitters.add(emitter);
            }

            @Override
            public void onResume(Emitter emitter, String lastEventId) throws IOException
            {
                onOpen(emitter);
            }

            @Override
            public void onClose()
            {
                emitters.remove(this.emitter);

            }

        }

    }
}