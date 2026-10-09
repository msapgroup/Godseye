# GODSEYE screen gallery

These screenshots were captured directly from a running GODSEYE test instance using `scripts/capture_ui.py`. The refreshed theme is applied by the app itself, including card borders, search controls, login, realistic device artwork, and the personal dashboard. Demonstration endpoints and traffic samples are confined to the screenshot fixture; production displays its own records. The Windows Agent installer screenshots continue to document the unchanged Agent 2.4.5 setup.

[Custom dashboard instructions and every refreshed page](CUSTOM_DASHBOARD.md)

## Sign in

![Sign in](screenshots/v431-login.png)

Sign in to manage network devices, investigate findings, coordinate service work, and control your self-hosted environment.

## Dashboard

![Dashboard](screenshots/v431-dashboard-map-logo.png)

Review device totals, findings, monitored services, tickets, traffic, alerts, and the Network Map overview from one operator workspace.

## Devices

![Devices](screenshots/v431-devices-guide.png)

Search and filter network assets, discover the network, add authorized devices, select a device for details, and review recent device activity.

## Network Map

![Network Map](screenshots/v431-network-map-card.png)

Inspect observed device relationships and move from the visual map into the related inventory records.

## Sites

![Sites management](screenshots/v431-sites-management.png)

The capture pairs two running GODSEYE instances over HTTPS and opens the remote location card. On a remote installation, generate a one-time token in Sites; on the master, enter its VPN-reachable HTTPS address, a name, and the token. Open its card to manage devices, findings, and tickets. Add a trusted PEM certificate when the remote uses a private CA. Revoke the paired master on the remote installation to end access.

## CRM

![CRM customer record](screenshots/v431-crm-live.png)

Open **CRM** in the sidebar. Click **Add Customer**, enter the name and details, optionally select a linked GODSEYE site, then save. The new customer card closes after a successful save; select the saved card from the list to open it again. Use **Add contact** to record each person's name, role, email, and phone. Search by customer name or email. Operators and administrators can edit; administrators can delete. Use **Upload files** to attach pictures and documents to saved customers, and **Download** or **Remove** to manage them. Attach documents and pictures after saving the customer. This capture shows a saved sample record from the running app; CRM reads and writes records in the local GODSEYE database.

## Knowledge Base

![Outlook setup guide in GODSEYE](screenshots/v431-kb-outlook-guide.png)

Open **Knowledge Base** and search for a keyword in article content or steps. Choose the seeded Outlook setup guide to read its numbered steps and illustrated images. Select **New article** to write a guide, then save and upload pictures. In **Edit article**, use **Copy image URL** on an uploaded picture to add it to a numbered step. Administrators can delete old articles, including their uploaded files.

![New article editor](screenshots/v431-kb-new-article.png)

Fill in the article title, product, optional customer/site, description, prerequisites, steps, troubleshooting, and official source links. Save to close the new article card and enable attachments; select **Open article** to return to the saved guide. Each image is an illustration of the Outlook flow; consult the linked Microsoft article for the current product UI.

## Calendar

![Calendar](screenshots/v431-calendar-guide.png)

Plan maintenance and ticket work with Month, Week, Day, or List views and supported calendar connections.

## Email

![Email](screenshots/v431-email-guide.png)

Connect a supported mailbox, browse messages, reply, and share generated GODSEYE reports from the operational workspace.

## System Health

![System Health](screenshots/v431-system-health-guide.png)

Review web service, scanner, database, backups, notifications, integrations, CPU, memory, disk, storage, network activity, uptime, retention, updates, services, and logs.

## Users & Permissions · Reset password

![Admin password reset card](screenshots/v431-user-password-reset.png)

Only an Admin can reset another user's password. Open **Users & Permissions**, choose **Reset password** beside the user, enter and confirm a temporary password, then submit. The card closes after success. Share the temporary password securely; the user's sessions end and they must change it on their next sign-in. MFA remains enabled. For your own password, use **Change Password** in account settings.

## Remote Access

![Remote Access](screenshots/v431-remote-access-guide.png)

Select an enrolled online Windows computer, request a consent-based screen-sharing session, and separately request control when needed.

## Windows Event Findings

![Windows Event Findings](screenshots/v431-event-findings-guide.png)

Review collected Windows events, open Suggested Fix guidance, recheck the condition, resolve the finding, or create a linked ticket.

## Cyber Tools

![Cyber Tools](screenshots/v431-cyber-tools-overview.png)

Run bounded, authorized security and diagnostic checks from eight focused tool cards.

## Cyber Tools result and history

![Cyber Tools result](screenshots/v431-cyber-tools-working.png)

Review structured results and scan history, create Findings or Tickets where supported, export results, or schedule recurring supported checks.

## About GODSEYE

![About GODSEYE](screenshots/godseye-about.png)

The About workspace explains GODSEYE's network intelligence, security operations, MSP workflows, and self-hosted control, with links to setup and technical documentation.


## License & Legal Notice

![License and Legal Notice](screenshots/v431-about-license-notice.png)

Open **About → License & Legal Notice** to read the notice. **View GNU GPL v3.0** opens the locally bundled complete license. Close using **Close**, **×**, or **Escape**.

## Terms of Use

![Terms of Use](screenshots/v431-about-terms-of-use.png)

Open **About → Terms of Use** beneath the About-page links. Review responsibilities for access, data, backups, scans, updates, third-party products, and liability. The notices preserve GPL rights.
