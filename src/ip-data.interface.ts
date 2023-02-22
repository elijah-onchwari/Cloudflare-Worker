
export interface IpDataResponse {
  [key: string]: any;
  is_tor?: boolean;
  is_icloud_relay?: boolean;
  is_proxy?: boolean;
  is_datacenter?: boolean;
  is_anonymous?: boolean;
  is_known_attacker?: boolean;
  is_known_abuser?: boolean;
  is_threat?: boolean;
  is_bogon?: boolean;
  blocklists?: any[];
}
