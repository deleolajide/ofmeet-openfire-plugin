/*
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
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

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.http.HttpBindManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.plugin.rest.entity.SystemProperties;
import org.jivesoftware.openfire.plugin.rest.entity.SystemProperty;
import org.jivesoftware.openfire.plugin.rest.exceptions.ExceptionType;
import org.jivesoftware.openfire.plugin.rest.exceptions.ServiceException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventDispatcher;
import org.jivesoftware.util.PropertyEventListener;
import org.jivesoftware.util.StringUtils;

import org.jivesoftware.openfire.plugin.rest.service.JerseyWrapper;

import org.eclipse.jetty.apache.jsp.JettyJasperInitializer;
import org.eclipse.jetty.plus.annotation.ContainerInitializer;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.WebAppContext;

import org.eclipse.jetty.util.security.*;
import org.eclipse.jetty.security.*;
import org.eclipse.jetty.security.authentication.*;

import org.apache.tomcat.InstanceManager;
import org.apache.tomcat.SimpleInstanceManager;
import org.jivesoftware.openfire.plugin.spark.BookmarkInterceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class RESTServicePlugin.
 */
public class RESTServicePlugin implements Plugin, PropertyEventListener {
    private static final Logger Log = LoggerFactory.getLogger(RESTServicePlugin.class);

    /** The Constant INSTANCE. */
    public static final RESTServicePlugin INSTANCE = new RESTServicePlugin();

    private static final String CUSTOM_AUTH_FILTER_PROPERTY_NAME = "plugin.ofchat.customAuthFilter";

    /** The secret. */
    private String secret;

    /** The allowed i ps. */
    private Collection<String> allowedIPs;

    /** The enabled. */
    private boolean enabled;

    /** The http auth. */
    private String httpAuth;

    /** The custom authentication filter */
    private String customAuthFilterClassName;

    private BookmarkInterceptor bookmarkInterceptor;
    private ServletContextHandler context;
    private ServletContextHandler context2;
    private ServletContextHandler context3;


    /**
     * Gets the single instance of RESTServicePlugin.
     *
     * @return single instance of RESTServicePlugin
     */
    public static RESTServicePlugin getInstance() {
        return INSTANCE;
    }

    /* (non-Javadoc)
     * @see org.jivesoftware.openfire.container.Plugin#initializePlugin(org.jivesoftware.openfire.container.PluginManager, java.io.File)
     */
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        secret = JiveGlobals.getProperty("plugin.restapi.secret", "");
        // If no secret key has been assigned, assign a random one.
        if ("".equals(secret)) {
            secret = StringUtils.randomString(16);
            setSecret(secret);
        }

        Log.info("Initialize REST");

        // See if Custom authentication filter has been defined
        customAuthFilterClassName = JiveGlobals.getProperty("plugin.restapi.customAuthFilter", "");

        // See if the service is enabled or not.
        enabled = JiveGlobals.getBooleanProperty("plugin.restapi.enabled", false);

        // See if the HTTP Basic Auth is enabled or not.
        httpAuth = JiveGlobals.getProperty("plugin.restapi.httpAuth", "basic");

        // Get the list of IP addresses that can use this service. An empty list
        // means that this filter is disabled.
        allowedIPs = StringUtils.stringToCollection(JiveGlobals.getProperty("plugin.restapi.allowedIPs", ""));

        // Listen to system property events
        PropertyEventDispatcher.addListener(this);

        // start REST service on http-bind port
        context = new ServletContextHandler(null, "/rest", ServletContextHandler.SESSIONS);
        context.setClassLoader(this.getClass().getClassLoader());
        context.addServlet(new ServletHolder(new JerseyWrapper()), "/api/*");

        // Ensure the JSP engine is initialized correctly (in order to be
        // able to cope with Tomcat/Jasper precompiled JSPs).

        final List<ContainerInitializer> initializers = new ArrayList<>();
        initializers.add(new ContainerInitializer(new JettyJasperInitializer(), null));
        context.setAttribute("org.eclipse.jetty.containerInitializers", initializers);
        context.setAttribute(InstanceManager.class.getName(), new SimpleInstanceManager());

        HttpBindManager.getInstance().addJettyHandler(context);

/*
        Log.info("Initialize SSE");

        context2 = new ServletContextHandler(null, "/event", ServletContextHandler.SESSIONS);
        context2.setClassLoader(this.getClass().getClassLoader());

        ServletHolder sseHolder = new ServletHolder(new RestEventSourceServlet());
        sseHolder.setAsyncSupported(true);
        context2.addServlet(sseHolder, "/source");

        final List<ContainerInitializer> initializers3 = new ArrayList<>();
        initializers3.add(new ContainerInitializer(new JettyJasperInitializer(), null));
        context2.setAttribute("org.eclipse.jetty.containerInitializers", initializers);
        context2.setAttribute(InstanceManager.class.getName(), new SimpleInstanceManager());

        HttpBindManager.getInstance().addJettyHandler(context2);
*/

        Log.info("Initialize WebService ");

        WebAppContext context3 = new WebAppContext(null, pluginDirectory.getPath() + "/classes", "/ofchat");
        context3.setClassLoader(this.getClass().getClassLoader());

        // Ensure the JSP engine is initialized correctly (in order to be able to cope with Tomcat/Jasper precompiled JSPs).

        final List<ContainerInitializer> initializers3 = new ArrayList<>();
        initializers3.add(new ContainerInitializer(new JettyJasperInitializer(), null));
        context3.setAttribute("org.eclipse.jetty.containerInitializers", initializers3);
        context3.setAttribute(InstanceManager.class.getName(), new SimpleInstanceManager());
        context3.setWelcomeFiles(new String[]{"index.jsp"});

        HttpBindManager.getInstance().addJettyHandler(context3);

        bookmarkInterceptor = new BookmarkInterceptor();
        bookmarkInterceptor.start();
    }

    /* (non-Javadoc)
     * @see org.jivesoftware.openfire.container.Plugin#destroyPlugin()
     */
    public void destroyPlugin() {
        // Stop listening to system property events
        PropertyEventDispatcher.removeListener(this);

        if ( bookmarkInterceptor != null )
        {
            bookmarkInterceptor.stop();
            bookmarkInterceptor = null;
        }

        HttpBindManager.getInstance().removeJettyHandler(context);
        //HttpBindManager.getInstance().removeJettyHandler(context2);
       HttpBindManager.getInstance().removeJettyHandler(context3);
    }

    /**
     * Gets the system properties.
     *
     * @return the system properties
     */
    public SystemProperties getSystemProperties() {
        SystemProperties systemProperties = new SystemProperties();
        List<SystemProperty> propertiesList = new ArrayList<SystemProperty>();

        for(String propertyKey : JiveGlobals.getPropertyNames()) {
            String propertyValue = JiveGlobals.getProperty(propertyKey);
            propertiesList.add(new SystemProperty(propertyKey, propertyValue));
        }
        systemProperties.setProperties(propertiesList);
        return systemProperties;

    }

    /**
     * Gets the system property.
     *
     * @param propertyKey the property key
     * @return the system property
     * @throws ServiceException the service exception
     */
    public SystemProperty getSystemProperty(String propertyKey) throws ServiceException {
        String propertyValue = JiveGlobals.getProperty(propertyKey);
        if(propertyValue != null) {
        return new SystemProperty(propertyKey, propertyValue);
        } else {
            throw new ServiceException("Could not find property", propertyKey, ExceptionType.PROPERTY_NOT_FOUND,
                    Response.Status.NOT_FOUND);
        }
    }

    /**
     * Creates the system property.
     *
     * @param systemProperty the system property
     */
    public void createSystemProperty(SystemProperty systemProperty) {
        JiveGlobals.setProperty(systemProperty.getKey(), systemProperty.getValue());
    }

    /**
     * Delete system property.
     *
     * @param propertyKey the property key
     * @throws ServiceException the service exception
     */
    public void deleteSystemProperty(String propertyKey) throws ServiceException {
        if(JiveGlobals.getProperty(propertyKey) != null) {
            JiveGlobals.deleteProperty(propertyKey);
        } else {
            throw new ServiceException("Could not find property", propertyKey, ExceptionType.PROPERTY_NOT_FOUND,
                    Response.Status.NOT_FOUND);
        }
    }

    /**
     * Update system property.
     *
     * @param propertyKey the property key
     * @param systemProperty the system property
     * @throws ServiceException the service exception
     */
    public void updateSystemProperty(String propertyKey, SystemProperty systemProperty) throws ServiceException {
        if(JiveGlobals.getProperty(propertyKey) != null) {
            if(systemProperty.getKey().equals(propertyKey)) {
                JiveGlobals.setProperty(propertyKey, systemProperty.getValue());
            } else {
                throw new ServiceException("Path property name and entity property name doesn't match", propertyKey, ExceptionType.ILLEGAL_ARGUMENT_EXCEPTION,
                        Response.Status.BAD_REQUEST);
            }
        } else {
            throw new ServiceException("Could not find property for update", systemProperty.getKey(), ExceptionType.PROPERTY_NOT_FOUND,
                    Response.Status.NOT_FOUND);
        }
    }


    /**
     * Returns the loading status message.
     *
     * @return the loading status message.
     */
    public String getLoadingStatusMessage() {
        return JerseyWrapper.getLoadingStatusMessage();
    }

    /**
     * Reloads the Jersey wrapper.
     */
    public String loadAuthenticationFilter(String customAuthFilterClassName) {
        return JerseyWrapper.tryLoadingAuthenticationFilter(customAuthFilterClassName);
    }

    /**
     * Returns the secret key that only valid requests should know.
     *
     * @return the secret key.
     */
    public String getSecret() {
        return secret;
    }

    /**
     * Sets the secret key that grants permission to use the userservice.
     *
     * @param secret
     *            the secret key.
     */
    public void setSecret(String secret) {
        JiveGlobals.setProperty("plugin.restapi.secret", secret);
        this.secret = secret;
    }

    /**
     * Returns the custom authentication filter class name used in place of the basic ones to grant permission to use the Rest services.
     *
     * @return custom authentication filter class name .
     */
    public String getCustomAuthFilterClassName() {
        return customAuthFilterClassName;
    }

    /**
     * Sets the customAuthFIlterClassName used to grant permission to use the Rest services.
     *
     * @param customAuthFilterClassName
     *            custom authentication filter class name.
     */
    public void setCustomAuthFiIterClassName(String customAuthFilterClassName) {
        JiveGlobals.setProperty(CUSTOM_AUTH_FILTER_PROPERTY_NAME, customAuthFilterClassName);
        this.customAuthFilterClassName = customAuthFilterClassName;
    }

    /**
     * Gets the allowed i ps.
     *
     * @return the allowed i ps
     */
    public Collection<String> getAllowedIPs() {
        return allowedIPs;
    }

    /**
     * Sets the allowed i ps.
     *
     * @param allowedIPs the new allowed i ps
     */
    public void setAllowedIPs(Collection<String> allowedIPs) {
        JiveGlobals.setProperty("plugin.restapi.allowedIPs", StringUtils.collectionToString(allowedIPs));
        this.allowedIPs = allowedIPs;
    }

    /**
     * Returns true if the user service is enabled. If not enabled, it will not
     * accept requests to create new accounts.
     *
     * @return true if the user service is enabled.
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables or disables the user service. If not enabled, it will not accept
     * requests to create new accounts.
     *
     * @param enabled
     *            true if the user service should be enabled.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        JiveGlobals.setProperty("plugin.restapi.enabled", enabled ? "true" : "false");
    }

    /**
     * Gets the http authentication mechanism.
     *
     * @return the http authentication mechanism
     */
    public String getHttpAuth() {
        return httpAuth;
    }

    /**
     * Sets the http auth.
     *
     * @param httpAuth the new http auth
     */
    public void setHttpAuth(String httpAuth) {
        this.httpAuth = httpAuth;
        JiveGlobals.setProperty("plugin.restapi.httpAuth", httpAuth);
    }

    /* (non-Javadoc)
     * @see org.jivesoftware.util.PropertyEventListener#propertySet(java.lang.String, java.util.Map)
     */
    public void propertySet(String property, Map<String, Object> params) {
        if (property.equals("plugin.restapi.secret")) {
            this.secret = (String) params.get("value");
        } else if (property.equals("plugin.restapi.enabled")) {
            this.enabled = Boolean.parseBoolean((String) params.get("value"));
        } else if (property.equals("plugin.restapi.allowedIPs")) {
            this.allowedIPs = StringUtils.stringToCollection((String) params.get("value"));
        } else if (property.equals("plugin.restapi.httpAuth")) {
            this.httpAuth = (String) params.get("value");
        } else if(property.equals(CUSTOM_AUTH_FILTER_PROPERTY_NAME)) {
            this.customAuthFilterClassName = (String) params.get("value");
        }
    }

    /* (non-Javadoc)
     * @see org.jivesoftware.util.PropertyEventListener#propertyDeleted(java.lang.String, java.util.Map)
     */
    public void propertyDeleted(String property, Map<String, Object> params) {
        if (property.equals("plugin.restapi.secret")) {
            this.secret = "";
        } else if (property.equals("plugin.restapi.enabled")) {
            this.enabled = false;
        } else if (property.equals("plugin.restapi.allowedIPs")) {
            this.allowedIPs = Collections.emptyList();
        } else if (property.equals("plugin.restapi.httpAuth")) {
            this.httpAuth = "basic";
        } else if(property.equals(CUSTOM_AUTH_FILTER_PROPERTY_NAME)) {
            this.customAuthFilterClassName = null;
        }
    }

    /* (non-Javadoc)
     * @see org.jivesoftware.util.PropertyEventListener#xmlPropertySet(java.lang.String, java.util.Map)
     */
    public void xmlPropertySet(String property, Map<String, Object> params) {
        // Do nothing
    }

    /* (non-Javadoc)
     * @see org.jivesoftware.util.PropertyEventListener#xmlPropertyDeleted(java.lang.String, java.util.Map)
     */
    public void xmlPropertyDeleted(String property, Map<String, Object> params) {
        // Do nothing
    }

    public void addServlet(ServletHolder holder)
    {
       context.addServlet(holder, path);
    }

    public void removeServlets(ServletHolder deleteHolder)
    {
       ServletHandler handler = context.getServletHandler();
       List<ServletHolder> servlets = new ArrayList<ServletHolder>();
       Set<String> names = new HashSet<String>();

       for( ServletHolder holder : handler.getServlets() )
       {
          if(deleteHolder.isInstance(holder.getServlet()))
          {
              names.add(holder.getName());
          }
          else /* We keep it */
          {
              servlets.add(holder);
          }
       }

       List<ServletMapping> mappings = new ArrayList<ServletMapping>();

       for( ServletMapping mapping : handler.getServletMappings() )
       {
          /* Only keep the mappings that didn't point to one of the servlets we removed */

          if(!names.contains(mapping.getServletName()))
          {
              mappings.add(mapping);
          }
       }

       /* Set the new configuration for the mappings and the servlets */

       handler.setServletMappings( mappings.toArray(new ServletMapping[0]) );
       handler.setServlets( servlets.toArray(new ServletHolder[0]) );
    }
}
