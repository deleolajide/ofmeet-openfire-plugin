call mvn clean package

rd "C:\openfire_temp\plugins\ofmeet" /q /s
rd "C:\openfire_temp\plugins\ofocus" /q /s
rd "C:\openfire_temp\plugins\ofswitch" /q /s
rd "C:\openfire_temp\plugins\ofchat" /q /s

del "C:\openfire_temp\plugins\ofmeet.jar" 
del "C:\openfire_temp\plugins\ofocus.jar" 
del "C:\openfire_temp\plugins\ofswitch.jar" 
del "C:\openfire_temp\plugins\ofchat.jar" 

copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofmeet\target\ofmeet.jar "C:\openfire_temp\plugins"
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\offocus\target\ofocus.jar "C:\openfire_temp\plugins"
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofswitch\target\ofswitch.jar "C:\openfire_temp\plugins"
copy C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofchat\target\ofchat.jar "C:\openfire_temp\plugins"

rd /s /q C:\Projects\ignite\ofmeet-openfire-plugin-dele\ofswitch\classes\jitsi-meet
del "C:\openfire_temp\logs\*.*"
pause