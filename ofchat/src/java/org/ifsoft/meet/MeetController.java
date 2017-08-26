package org.ifsoft.meet;

import java.util.*;
import java.util.concurrent.*;
import java.io.*;
import java.security.*;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.SessionManager;
import org.jivesoftware.util.*;
import org.jivesoftware.openfire.group.*;
import org.jivesoftware.openfire.user.*;
import org.jivesoftware.openfire.session.*;

import org.xmpp.packet.*;
import org.jivesoftware.openfire.plugin.rawpropertyeditor.RawPropertyEditor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.sf.json.*;
import org.xmpp.packet.*;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import org.apache.http.HttpResponse;
import nl.martijndwars.webpush.*;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/**
 * The Class MeetController.
 */
public class MeetController {

    private static final Logger Log = LoggerFactory.getLogger(MeetController.class);
    public static final MeetController INSTANCE = new MeetController();

    /**
     * Gets the instance.
     *
     * @return the instance
     */
    public static MeetController getInstance() {
        return INSTANCE;
    }

    //-------------------------------------------------------
    //
    //  Web Push
    //
    //-------------------------------------------------------

    /**
     * push a payload to all subscribed web push resources of a user
     *
     */
    public boolean postWebPush(String username, String payload)
    {
        Log.debug("postWebPush "  + username + "\n" + payload);

        User user = RawPropertyEditor.getInstance().getAndCheckUser(username);
        if (user == null) return false;
        boolean ok = false;

        String publicKey = user.getProperties().get("vapid.public.key");
        String privateKey = user.getProperties().get("vapid.private.key");

        try {
            if (publicKey != null && privateKey != null)
            {
                PushService pushService = new PushService()
                    .setPublicKey(publicKey)
                    .setPrivateKey(privateKey)
                    .setSubject("mailto:admin@" + XMPPServer.getInstance().getServerInfo().getXMPPDomain());

                Log.debug("postWebPush keys \n"  + publicKey + "\n" + privateKey);

                for (String key : user.getProperties().keySet())
                {
                    if (key.startsWith("webpush.subscribe."))
                    {
                        try {
                            Subscription subscription = new Gson().fromJson(user.getProperties().get(key), Subscription.class);
                            Notification notification = new Notification(subscription, payload);
                            HttpResponse response = pushService.send(notification);
                            int statusCode = response.getStatusLine().getStatusCode();

                            ok = (200 == statusCode) || (201 == statusCode);

                            Log.debug("postWebPush delivered "  + statusCode + "\n" + response);


                        } catch (Exception e) {
                            Log.error("postWebPush failed "  + username + "\n" + payload, e);
                        }
                    }
                }

            }
        } catch (Exception e1) {
            Log.error("postWebPush failed "  + username + "\n" + payload, e1);
        }

        return ok;
    }

    /**
     * store web push subscription as a user property
     *
     */
    public boolean putWebPushSubscription(String username, String resource, String subscription)
    {
        Log.debug("putWebPushSubscription "  + username + " " + resource + "\n" + subscription);

        User user = RawPropertyEditor.getInstance().getAndCheckUser(username);
        if (user == null) return false;

        user.getProperties().put("webpush.subscribe." + resource, subscription);
        return true;
    }

    /**
     * generate a new public/private key pair for VAPID and store in system properties
     * and user properties
     */
    public String getWebPushPublicKey(String username)
    {
        Log.debug("getWebPushPublicKey " + username);

        String ofPublicKey = null;
        String ofPrivateKey = null;

        User user = RawPropertyEditor.getInstance().getAndCheckUser(username);
        if (user == null) return null;

        ofPublicKey = user.getProperties().get("vapid.public.key");
        ofPrivateKey = user.getProperties().get("vapid.private.key");

        if (ofPublicKey == null || ofPrivateKey == null)
        {
            try {
                KeyPair keyPair = generateKeyPair();

                byte[] publicKey = Utils.savePublicKey((ECPublicKey) keyPair.getPublic());
                byte[] privateKey = Utils.savePrivateKey((ECPrivateKey) keyPair.getPrivate());

                ofPublicKey = BaseEncoding.base64Url().encode(publicKey);
                ofPrivateKey = BaseEncoding.base64Url().encode(privateKey);

                user.getProperties().put("vapid.public.key", ofPublicKey);
                JiveGlobals.setProperty("vapid.public.key", ofPublicKey);

                user.getProperties().put("vapid.private.key", ofPrivateKey);
                JiveGlobals.setProperty("vapid.private.key", ofPrivateKey);

            } catch (Exception e) {
                Log.error("getWebPushPublicKey", e);
            }

        } else {
            user.getProperties().put("vapid.public.key", ofPublicKey);
            user.getProperties().put("vapid.private.key", ofPrivateKey);
        }

        return ofPublicKey;
    }

    /**
     * Generate an EC keypair on the prime256v1 curve.
     *
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    private KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(parameterSpec);

        return keyPairGenerator.generateKeyPair();
    }
}