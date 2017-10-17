call "C:\Apache Software Foundation\apache-maven-3.5.0\bin\mvn" package

rd "C:\openfire_4_1_6\plugins\ofmeet" /q /s
rd "C:\openfire_4_1_6\plugins\ofocus" /q /s
rd "C:\openfire_4_1_6\plugins\ofswitch" /q /s
rd "C:\openfire_4_1_6\plugins\ofchat" /q /s

del "C:\openfire_4_1_6\plugins\ofmeet.jar" 
del "C:\openfire_4_1_6\plugins\ofocus.jar" 
del "C:\openfire_4_1_6\plugins\ofswitch.jar" 
del "C:\openfire_4_1_6\plugins\ofchat.jar" 

copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofmeet\target\ofmeet.jar "C:\openfire_4_1_6\plugins"
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\offocus\target\ofocus.jar "C:\openfire_4_1_6\plugins"
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofswitch\target\ofswitch.jar "C:\openfire_4_1_6\plugins"
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofchat\target\ofchat.jar "C:\openfire_4_1_6\plugins"

rd /s /q C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofswitch\classes\jitsi-meet
del "C:\openfire_4_1_6\logs\*.*"
pause