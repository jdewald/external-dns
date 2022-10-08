package stackpath

import (
	"context"
	"fmt"
	"strings"

	spapi "git.lan.40two.org/jdewald/stackpath-dns-go.git/pkg/api"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

type DNSAction string

const (
	ActionDelete DNSAction = "delete"
	ActionCreate DNSAction = "create"
)

type StackpathDNSProvider struct {
	provider.BaseProvider
	ttl          int64
	ctx          context.Context
	spdns        *spapi.StackDNS
	domainFilter endpoint.DomainFilter
	dryRun       bool
}

func NewStackpathDNSProvider(ctx context.Context, domainFilter endpoint.DomainFilter, ttl int64, clientId, clientSecret, stackId string, dryRun bool) (*StackpathDNSProvider, error) {

	spdns, err := newSPDNSClient("", clientId, clientSecret, stackId)
	if err != nil {
		return nil, err
	}
	spProvider := &StackpathDNSProvider{
		ttl:          ttl,
		ctx:          ctx,
		spdns:        spdns,
		domainFilter: domainFilter,
		dryRun:       dryRun,
	}

	return spProvider, nil
}

func (sp *StackpathDNSProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {

	zones := sp.spdns.Zones()

	allowedZones := []spapi.Zone{}

	for _, zone := range zones {
		if sp.domainFilter.Match(zone.Name()) {
			allowedZones = append(allowedZones, zone)
			log.Debugf("StackPath: %s zone found", zone.Name())
		}

	}

	endpoints := []*endpoint.Endpoint{}
	for _, zone := range allowedZones {
		recordSets := zone.RecordSets()

		for recordSets.HasNext() {

			rs := recordSets.Next()

			targets := make([]string, len(rs.Records()))

			ttl := 0
			for i, d := range rs.Records() {
				targets[i] = d.Data()
				if d.TTL() > int32(ttl) {
					ttl = int(d.TTL())
				}
			}

			endpoint := &endpoint.Endpoint{
				DNSName:          fmt.Sprintf("%s.%s", rs.Name(), zone.Name()),
				Targets:          targets,
				RecordType:       rs.Type(),
				SetIdentifier:    "",
				RecordTTL:        endpoint.TTL(ttl),
				Labels:           map[string]string{}, // TODO: can be some owner metadata here
				ProviderSpecific: []endpoint.ProviderSpecificProperty{},
			}

			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints, nil
}

func endpointToRecordSet(zones []spapi.Zone, e *endpoint.Endpoint, action DNSAction, rsCache map[string]spapi.RecordSet, dryRun bool, defaultTTL int64, updatedRS map[string][]spapi.RecordSet) (spapi.RecordSet, error) {
	dn := e.DNSName
	var zone spapi.Zone

	// def getZone
	for _, z := range zones {
		if z.Name() == dn || strings.HasSuffix(dn, "."+z.Name()) {

			zone = z
			break
		}
	}

	if zone == nil {
		return nil, fmt.Errorf("unable to find zone for %s", dn)
	}
	domain := strings.TrimSuffix(dn, "."+zone.Name())
	recordType := e.RecordType

	var rs spapi.RecordSet
	var ok bool
	if rs, ok = rsCache[zone.Name()+"::"+domain+"::"+recordType]; !ok {
		rs = zone.RecordSet(domain, recordType)

		rsCache[zone.Name()+"::"+domain+"::"+recordType] = rs
		if _, ok := updatedRS[zone.Name()]; !ok {
			updatedRS[zone.Name()] = make([]spapi.RecordSet, 0)
		}
		updatedRS[zone.Name()] = append(updatedRS[zone.Name()], rs)
	}

	for _, target := range e.Targets {
		if action == ActionCreate {
			ttl := e.RecordTTL
			if !ttl.IsConfigured() {
				ttl = endpoint.TTL(defaultTTL)
			}
			if dryRun {
				log.Infof("DRYRUN: Would create %s [%s].%s with value %s of with TTL %d", recordType, domain, zone.Name(), target, ttl)
			} else {
				log.Debugf("Will create %s [%s].%s with value %s with TTL %d", recordType, domain, zone.Name(), target, ttl)
			}
			rs.Ensure(target, int32(ttl))
		} else {
			if dryRun {
				log.Infof("DRYRUN: Would delete %s [%s].%s with value %s", recordType, domain, zone.Name(), target)
			} else {
				log.Debugf("DRYRUN: Would delete %s [%s].%s with value %s", recordType, domain, zone.Name(), target)
			}
			rs.Remove(target)
		}
	}

	return rs, nil
}

func (sp *StackpathDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {

	if !changes.HasChanges() {
		return nil
	}

	rsCache := map[string]spapi.RecordSet{}
	zones := sp.spdns.Zones()

	updatedRS := make(map[string][]spapi.RecordSet, 0)

	apply := func(endpoints []*endpoint.Endpoint, action DNSAction) {

		for _, endpoint := range endpoints {
			_, err := endpointToRecordSet(zones, endpoint, action, rsCache, sp.dryRun, sp.ttl, updatedRS)
			if err != nil {
				log.Errorf("unable to apply change: %v", err)
				continue
			}

		}
	}

	apply(changes.Create, ActionCreate)
	apply(changes.Delete, ActionDelete)
	apply(changes.UpdateOld, ActionDelete)
	apply(changes.UpdateNew, ActionCreate)

	for zoneName, rrs := range updatedRS {
		if !sp.dryRun {
			log.Infof("Syncing recordset changes for %s", zoneName)
			err := sp.spdns.Zone(zoneName).Sync(rrs...)
			if err != nil {
				return err
			}
		}
		return nil

	}

	return nil
}

func newSPDNSClient(gatewayServer, clientID, clientSecret, stackID string) (*spapi.StackDNS, error) {

	server := "https://gateway.stackpath.com"
	if gatewayServer != "" {
		server = gatewayServer

	}

	dnsClient, err := spapi.NewDNSWithCredentials(server, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	sClient := dnsClient.WithStack(stackID)

	return sClient, nil

}
