/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.mobicents.protocols.ss7.sccp.impl.router;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;

/**
 * The default implementation for the SCCP router.
 * 
 * The SCCP router allows to add/remove/list routing rules and implements persistance for 
 * the routing rules.
 * 
 * @author kulikov
 */
public class RouterImpl {
    private Route route;
    
    private File file;
    
    private Logger logger = Logger.getLogger(RouterImpl.class);
    //rule list
    private ArrayList<Rule> rules = new ArrayList();
    
    public RouterImpl(String path) {
        try {
        	if(logger.isInfoEnabled())
        	{
        		logger.info("SCCP Router configuration file: "+path);
        	}
        	if(path == null)
        	{
        		throw new IOException("Path of configuration file must be supplied.");
        	}
            file = new File(path); 
            if(!file.exists())
            {	
            	throw new IOException("Could not locate file: "+path);
            }
            load();
        } catch (Exception e) {
            logger.warn("Can not load rules from configuration: " + path, e);
        }
    }
    /**
     * Adds new rule for routing.
     * 
     * @param rule the new rule to be added.
     */
    public void add(Rule rule) throws IOException {
        rule.setNo(rules.size());
        rules.add(rule);
        try {
            store(rule);
        } catch (Exception e) {
            rules.remove(rule);
            throw new IOException(e.getMessage());
        }
    }
    
    /**
     * Removes routing rule from router.
     * 
     * @param rule
     */
    public void remove(int no) throws IOException {
        rules.remove(no);
        //reorder rules
        int i = 0;
        for (Rule rule: rules) {
            rule.setNo(i++);
        }
        
        clean();
        for (Rule rule: rules) {
            store(rule);
        }        
    }
    
    /**
     * Looks up rule for translation.
     * 
     * @param calledParty called party address
     * @return the rule with match to the called party address
     */
    public Rule find(SccpAddress calledParty) {
        for (Rule rule : rules) {
            if (rule.matches(calledParty)) {
                return rule;
            }
        }
        return null;
    }
    
    /**
     * Gets the list of all rules.
     * 
     * @return list of rules.
     */
    public Collection<Rule> list() {
        return rules;
    }
    
    public void clean() throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(file, false));
        writer.write("");
        writer.flush();
        writer.close();
    }
    
    public Route route(SccpAddress calledPartyAddress) {
        return route;
    }
    
    private void store(Rule rule) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
        writer.write(rule.toString());
        writer.newLine();
        writer.flush();
        writer.close();
    }
    
    private void load() throws FileNotFoundException, IOException {
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line = null;
        while ((line = reader.readLine()) != null) {
            rules.add(Rule.getInstance(line));
        }
        reader.close();
    }
}
