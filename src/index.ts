import { IpDataResponse } from "./ip-data.interface";

addEventListener("fetch", (event: FetchEvent) => {
  event.respondWith(handleRequest(event.request));
});

export async function handleRequest(request: Request): Promise<Response> {
  try {
    // Get user's IP address from Cloudflare header
    const userAgent = request.headers.get("user-agent");
    const userIp = request.headers.get("cf-connecting-ip");



    if (userAgent) {
      // Override for specific bots
      if (
        [
          "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
          "RevenueCat",
          "pusher-webhooks",
        ].includes(userAgent)
      ) {
        return fetch(request);
      }
    }

    if (userIp) {
      // Check if the IP address is approved in the KV store
      const ipStatus = await IPS.get(userIp);
      const isApproved = ipStatus ? JSON.parse(ipStatus) : null;

      if (isApproved) {
        console.log(
          `User IP address is whitelisted in the KV store: ${userIp}`
        );
        return fetch(request);
      }

      if (ipStatus === null || ipStatus === "undefined") {
        // IP not approved, check API response
        const apiKey =
          "XXXX"; // Replace with your own API key
        const apiUrl = `https://api.ipdata.co/${userIp}/threat?api-key=${apiKey}`;
        const apiResponse = await fetch(apiUrl, {
          headers: { "Content-Type": "application/json" },
        });

        if (!apiResponse.ok) {
          throw new Error(
            `API request failed with status ${apiResponse.status}`
          );
        }

        const json: IpDataResponse = await apiResponse.json();
        console.log("Ipdata Response: ", JSON.stringify(json));

        const isThreat = [
          "is_tor",
          "is_icloud_relay",
          "is_proxy",
          "is_datacenter",
          "is_anonymous",
          "is_known_attacker",
          "is_known_abuser",
          "is_threat",
          "is_bogon",
        ].some((prop) => !!json[prop]);

        if (!isThreat) {
          console.log(`User IP address approved by Ipdata: ${userIp}`);
          // IP approved, add to KV
          await IPS.put(userIp, JSON.stringify(true), { expirationTtl: 86400 });
          return fetch(request);
        } else {
          // IP denied, block traffic
          console.log(`User IP address flagged by Ipdata: ${userIp}`);
          await IPS.put(userIp, JSON.stringify(false), {
            expirationTtl: 86400,
          });
          return new Response("Access Denied", { status: 403 });
        }
      }

      console.log(`User IP address is blacklisted in the KV store: ${userIp}`);
      return new Response("Access Denied", { status: 403 });
    }

    return new Response("Unable to determine IP address or User Agent", {
      status: 400,
    });
  } catch (error) {
    console.error(error);
    return new Response("An error occurred", { status: 500 });
  }
}
