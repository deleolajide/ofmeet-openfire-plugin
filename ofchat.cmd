call "C:\Apache Software Foundation\apache-maven-3.5.0\bin\mvn" package

rd "C:\openfire_temp\plugins\ofchat" /q /s
del "C:\openfire_temp\plugins\ofchat.jar" 
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofchat\target\ofchat.jar "C:\openfire_temp\plugins"

rd /s /q C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofswitch\classes\jitsi-meet
del "C:\openfire_temp\logs\*.*"
pause