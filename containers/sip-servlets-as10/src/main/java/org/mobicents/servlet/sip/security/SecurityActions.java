/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2011-2015, Telestax Inc and individual contributors
 * by the @authors tag.
 *
 * This program is free software: you can redistribute it and/or modify
 * under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
package org.mobicents.servlet.sip.security;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.jboss.security.RunAs;
import org.jboss.security.RunAsIdentity;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.wildfly.extension.undertow.logging.UndertowLogger;


/**
 * taken from
 * https://github.com/jbossas/jboss-as/blob/7.1.2.Final/web/src/main/java/org/jboss/as/web/security/SecurityActions.java
 *
 * @author jean.deruelle@gmail.com
 *
 *         This class is based on org.mobicents.servlet.sip.security.SecurityActions class from sip-servlet-as7 project,
 *         re-implemented for jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 * @author balogh.gabor@alerant.hu
 *
 */
public class SecurityActions {
    /**
     * Create a JBoss Security Context with the given security domain name
     *
     * @param domain the security domain name (such as "other" )
     * @return an instanceof {@code SecurityContext}
     */
    public static SecurityContext createSecurityContext(final String domain) {
        return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>() {

            @Override
            public SecurityContext run() {
                try {
                    return SecurityContextFactory.createSecurityContext(domain);
                } catch (Exception e) {                    
                    throw UndertowLogger.ROOT_LOGGER.failToCreateSecurityContext(e);
                    
                }
            }
        });
    }

    /**
     * Set the {@code SecurityContext} on the {@code SecurityContextAssociation}
     *
     * @param sc the security context
     */
    public static void setSecurityContextOnAssociation(final SecurityContext sc) {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {

            @Override
            public Void run() {
                SecurityContextAssociation.setSecurityContext(sc);
                return null;
            }
        });
    }

    /**
     * Get the current {@code SecurityContext}
     *
     * @return an instance of {@code SecurityContext}
     */
    public static SecurityContext getSecurityContext() {
        return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>() {
            public SecurityContext run() {
                return SecurityContextAssociation.getSecurityContext();
            }
        });
    }

    /**
     * Clears current {@code SecurityContext}
     */
    public static void clearSecurityContext() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                SecurityContextAssociation.clearSecurityContext();
                return null;
            }
        });
    }

    /**
     * Sets the run as identity
     *
     * @param principal the identity
     */
    public static void pushRunAsIdentity(final RunAsIdentity principal) {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {

            @Override
            public Void run() {
                SecurityContext sc = getSecurityContext();
                if (sc == null)                    
                	throw UndertowLogger.ROOT_LOGGER.noSecurityContext();
                sc.setOutgoingRunAs(principal);
                return null;
            }
        });
    }

    /**
     * Removes the run as identity
     *
     * @return the identity removed
     */
    public static RunAs popRunAsIdentity() {
        return AccessController.doPrivileged(new PrivilegedAction<RunAs>() {

            @Override
            public RunAs run() {
                SecurityContext sc = getSecurityContext();
                if (sc == null)
                    throw UndertowLogger.ROOT_LOGGER.noSecurityContext();
                RunAs principal = sc.getOutgoingRunAs();
                sc.setOutgoingRunAs(null);
                return principal;
            }
        });
    }

    public static final String AUTH_EXCEPTION_KEY = "org.jboss.security.exception";

    public static void clearAuthException() {
        if (System.getSecurityManager() != null) {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {

                @Override
                public Void run() {
                    SecurityContext sc = getSecurityContext();
                    if (sc != null)
                        sc.getData().put(AUTH_EXCEPTION_KEY, null);
                    return null;
                }
            });
        } else {
            SecurityContext sc = getSecurityContext();
            if (sc != null)
                sc.getData().put(AUTH_EXCEPTION_KEY, null);
        }
    }

    public static Throwable getAuthException() {
        if (System.getSecurityManager() != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Throwable>() {

                @Override
                public Throwable run() {
                    SecurityContext sc = getSecurityContext();
                    Throwable exception = null;
                    if (sc != null)
                        exception = (Throwable) sc.getData().get(AUTH_EXCEPTION_KEY);
                    return exception;
                }
            });
        } else {
            SecurityContext sc = getSecurityContext();
            Throwable exception = null;
            if (sc != null)
                exception = (Throwable) sc.getData().get(AUTH_EXCEPTION_KEY);
            return exception;
        }
    }

    public static ClassLoader getContextClassLoader() {
        return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
            public ClassLoader run() {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }

    public static Void setContextClassLoader(final ClassLoader cl) {
        return AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Thread.currentThread().setContextClassLoader(cl);
                return null;
            }
        });
    }

    public static URL findResource(final URLClassLoader cl, final String name) {
        return AccessController.doPrivileged(new PrivilegedAction<URL>() {
            public URL run() {
                return cl.findResource(name);
            }
        });
    }

    public static InputStream openStream(final URL url) throws PrivilegedActionException {
        return AccessController.doPrivileged(new PrivilegedExceptionAction<InputStream>() {
            public InputStream run() throws IOException {
                return url.openStream();
            }
        });
    }

    public static Class<?> loadClass(final String name) throws PrivilegedActionException {
        return AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>() {
            public Class<?> run() throws ClassNotFoundException {
                ClassLoader[] cls = new ClassLoader[] { getContextClassLoader(), // User defined classes
                        SecurityActions.class.getClassLoader(), // PB classes (not always on TCCL [modular env])
                        ClassLoader.getSystemClassLoader() }; // System loader, usually has app class path

                ClassNotFoundException e = null;
                for (ClassLoader cl : cls) {
                    if (cl == null)
                        continue;
                    try {
                        return cl.loadClass(name);
                    } catch (ClassNotFoundException ce) {
                        e = ce;
                    }
                }
                throw e != null ? e : new ClassNotFoundException(name);
            }
        });
    }
}
