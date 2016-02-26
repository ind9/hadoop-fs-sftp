/*
 * Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.hadoop.fs.sftp;

import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.collect.Lists;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.util.Shell;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPassword;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.sftp.SftpSubsystem;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

public class TestSFTPFileSystem {

    private static final String TEST_SFTP_DIR = "testsftp";
    private static final String TEST_ROOT_DIR =
            System.getProperty("test.build.data", "build/test/data");

    @Rule public TestName name = new TestName();

    private static final String connection = "sftp://user:password@localhost";
    private static final String connectionWithouPassword = "sftp://user@localhost";
    private static final String dummyKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQDTb6056fGwtczLFM2I2qeCCatBdPgF2Gt0qH0toD8LaMEV52Kx\n" +
            "v8PyUXa1zZul90/nWCvcJgX/tSCYG8+u2eoVVp82bVrIbVfI8DB1qTJIwO3fROBs\n" +
            "ZDa5SwHs4sgQJlXB5QW1OuP0Zow9zUiYuMDcBakZLhkRGWmqYTEoHbelfQIDAQAB\n" +
            "AoGBALP0ceg/wBBZu3MBQqn/B+C6oAK3Lj2zZEnG+buyjtYEE4q0BCErCPgd875q\n" +
            "v9Xy9xP8zF+0ERkBLTupOAsmt35i9pw2TYYzmhLPrnuwKJeexe/qcz6BlI8BdJY4\n" +
            "LVIe59AUnKjH624HaxluIRlqNclcLpiSiJOi6AhUMeSxJ1UBAkEA+HndLgQ7cZ+S\n" +
            "u9ZRwKoyNIy7PFXDSMHDu7XaIbUqD9Pi/W3sEq95RlSwVRsyhzF/8efCZLiLkSI1\n" +
            "C8UYK9H0PQJBANnWsAuS6PiK15xQI1FjNk5p25OV7GsTcB5o+/kJRMAxLpv45OE7\n" +
            "O39FOJEEoeSWf5Yqz/fgqSr8BggcO3n7SkECQDfTCUJBaSmJ9GmHKS7kDguIYriX\n" +
            "fBxojBUsMinIjf6oWCMgAx3flpuag1NbnOqK0HgE3cPLQnAFA231hgyySvECQBd3\n" +
            "fTeB9/7uVhPMvkFCQtNnq/PWLsXKLkXYYWyOhw19Ptwmj+GDlAE9374flaEeZVgz\n" +
            "/HtjhFXRGIU/JVkarQECQQC+ebP9KFaQ5Q312H38LZfIiGHgQh75aYjeH8J1i/Ac\n" +
            "LCuCOXtm+vayM4WXYwyrPdjGhD6RNW5rot2QRNS0xIIz\n" +
            "-----END RSA PRIVATE KEY-----";
    private static Path localDir = null;
    private static FileSystem localFs = null;
    private static FileSystem sftpFs = null;
    private static FileSystem sftpFsWithKey = null;
    private static SshServer sshd = null;
    private static int port;

    private static void startSshdServer() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        // ask OS to assign a port
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());

        List<NamedFactory<UserAuth>> userAuthFactories =
                new ArrayList<NamedFactory<UserAuth>>();
        userAuthFactories.add(new UserAuthPassword.Factory());
        userAuthFactories.add(new UserAuthPublicKey.Factory());

        sshd.setUserAuthFactories(userAuthFactories);

        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password,
                                        ServerSession session) {
                if (username.equals("user") && password.equals("password")) {
                    return true;
                }
                return false;
            }
        });

        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return true;
            }
        });

        sshd.setSubsystemFactories(
                Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));

        sshd.start();
        port = sshd.getPort();
    }

    public static Configuration prepareConf() {
        Configuration conf = new Configuration();
        conf.setClass("fs.sftp.impl", SFTPFileSystem.class, FileSystem.class);
        conf.setInt("fs.sftp.host.port", port);
        conf.setBoolean("fs.sftp.impl.disable.cache", true);
        return  conf;
    }
    @BeforeClass
    public static void setUp() throws Exception {
        // skip all tests if running on Windows
        assumeTrue(!Shell.WINDOWS);

        startSshdServer();

        Configuration conf = prepareConf();

        localFs = FileSystem.getLocal(conf);
        localDir = localFs.makeQualified(new Path(TEST_ROOT_DIR, TEST_SFTP_DIR));
        if (localFs.exists(localDir)) {
            localFs.delete(localDir, true);
        }
        localFs.mkdirs(localDir);

        sftpFs = FileSystem.get(URI.create(connection), conf);
    }

    public static void setupWithKey() throws Exception {
        Configuration conf = prepareConf();
        conf.set(SFTPFileSystem.FS_SFTP_KEYSTRING, dummyKey);

        sftpFsWithKey = FileSystem.get(URI.create(connectionWithouPassword), conf);
    }

    @AfterClass
    public static void tearDown() {
        if (localFs != null) {
            try {
                localFs.delete(localDir, true);
                localFs.close();
            } catch (IOException e) {
                // ignore
            }
        }
        if (sftpFs != null) {
            try {
                sftpFs.close();
            } catch (IOException e) {
                // ignore
            }
        }
        if (sshd != null) {
            try {
                sshd.stop(true);
            } catch (InterruptedException e) {
                // ignore
            }
        }
    }

    private static final Path touch(FileSystem fs, String filename)
            throws IOException {
        return touch(fs, filename, null);
    }

    private static final Path touch(FileSystem fs, String filename, byte[] data)
            throws IOException {
        Path lPath = new Path(localDir.toUri().getPath(), filename);
        FSDataOutputStream out = null;
        try {
            out = fs.create(lPath);
            if (data != null) {
                out.write(data);
            }
        } finally {
            if (out != null) {
                out.close();
            }
        }
        return lPath;
    }

    /**
     * Creates a file and deletes it.
     *
     * @throws Exception
     */
    @Test
    public void testCreateFile() throws Exception {
        Path file = touch(sftpFs, name.getMethodName().toLowerCase());
        assertTrue(localFs.exists(file));
        assertTrue(sftpFs.delete(file, false));
        assertFalse(localFs.exists(file));
    }

    /**
     * Creates a file and deletes it.
     *
     * @throws Exception
     */
    @Test
    public void testCreateFileWithKeyAuth() throws Exception {
        setupWithKey();
        Path file = touch(sftpFsWithKey, name.getMethodName().toLowerCase());
        assertTrue(localFs.exists(file));
        assertTrue(sftpFs.delete(file, false));
        assertFalse(localFs.exists(file));
    }

    /**
     * Checks if a new created file exists.
     *
     * @throws Exception
     */
    @Test
    public void testFileExists() throws Exception {
        Path file = touch(localFs, name.getMethodName().toLowerCase());
        assertTrue(sftpFs.exists(file));
        assertTrue(localFs.exists(file));
        assertTrue(sftpFs.delete(file, false));
        assertFalse(sftpFs.exists(file));
        assertFalse(localFs.exists(file));
    }

    /**
     * Test writing to a file and reading its value.
     *
     * @throws Exception
     */
    @Test
    public void testReadFile() throws Exception {
        byte[] data = "yaks".getBytes();
        Path file = touch(localFs, name.getMethodName().toLowerCase(), data);
        FSDataInputStream is = null;
        try {
            is = sftpFs.open(file);
            byte[] b = new byte[data.length];
            is.read(b);
            assertArrayEquals(data, b);
        } finally {
            if (is != null) {
                is.close();
            }
        }
        assertTrue(sftpFs.delete(file, false));
    }

    /**
     * Test writing to a file and and seek its value from a middle pos.
     *
     * @throws Exception
     */
    @Test
    public void testSeekFile() throws Exception {
        byte[] data = "yaks".getBytes();
        Path file = touch(localFs, name.getMethodName().toLowerCase(), data);
        FSDataInputStream is = null;
        try {
            is = sftpFs.open(file);
            byte[] b = new byte[2];
            is.seek(2);
            is.read(b);
            assertArrayEquals("ks".getBytes(), b);

        } finally {
            if (is != null) {
                is.close();
            }
        }
        assertTrue(sftpFs.delete(file, false));
    }


    /**
     * Test getting the status of a file.
     *
     * @throws Exception
     */
    @Test
    public void testStatFile() throws Exception {
        byte[] data = "yaks".getBytes();
        Path file = touch(localFs, name.getMethodName().toLowerCase(), data);

        FileStatus lstat = localFs.getFileStatus(file);
        FileStatus sstat = sftpFs.getFileStatus(file);
        assertNotNull(sstat);

        assertEquals(lstat.getPath().toUri().getPath(),
                sstat.getPath().toUri().getPath());
        assertEquals(data.length, sstat.getLen());
        assertEquals(lstat.getLen(), sstat.getLen());
        assertTrue(sftpFs.delete(file, false));
    }

    /**
     * Test deleting a non empty directory.
     *
     * @throws Exception
     */
    @Test(expected=java.io.IOException.class)
    public void testDeleteNonEmptyDir() throws Exception {
        Path file = touch(localFs, name.getMethodName().toLowerCase());
        sftpFs.delete(localDir, false);
    }

    /**
     * Test deleting a file that does not exist.
     *
     * @throws Exception
     */
    @Test
    public void testDeleteNonExistFile() throws Exception {
        Path file = new Path(localDir, name.getMethodName().toLowerCase());
        assertFalse(sftpFs.delete(file, false));
    }

    /**
     * Test renaming a file.
     *
     * @throws Exception
     */
    @Test
    public void testRenameFile() throws Exception {
        byte[] data = "dingos".getBytes();
        Path file1 = touch(localFs, name.getMethodName().toLowerCase() + "1");
        Path file2 = new Path(localDir, name.getMethodName().toLowerCase() + "2");

        assertTrue(sftpFs.rename(file1, file2));

        assertTrue(sftpFs.exists(file2));
        assertFalse(sftpFs.exists(file1));

        assertTrue(localFs.exists(file2));
        assertFalse(localFs.exists(file1));

        assertTrue(sftpFs.delete(file2, false));
    }

    /**
     * Test renaming a file that does not exist.
     *
     * @throws Exception
     */
    @Test(expected=java.io.IOException.class)
    public void testRenameNonExistFile() throws Exception {
        Path file1 = new Path(localDir, name.getMethodName().toLowerCase() + "1");
        Path file2 = new Path(localDir, name.getMethodName().toLowerCase() + "2");
        sftpFs.rename(file1, file2);
    }

    /**
     * Test renaming a file onto an existing file.
     *
     * @throws Exception
     */
    @Test(expected=java.io.IOException.class)
    public void testRenamingFileOntoExistingFile() throws Exception {
        Path file1 = touch(localFs, name.getMethodName().toLowerCase() + "1");
        Path file2 = touch(localFs, name.getMethodName().toLowerCase() + "2");
        sftpFs.rename(file1, file2);
    }

}