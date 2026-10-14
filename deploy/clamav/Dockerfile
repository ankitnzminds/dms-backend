# ClamAV daemon for the DMS backend on Render (private service, TCP 3310).
# The official image downloads fresh virus signatures on start (freshclam) and then runs clamd.
# Pin a tag here to control when signatures/engine updates are rolled out.
FROM clamav/clamav:stable

EXPOSE 3310
