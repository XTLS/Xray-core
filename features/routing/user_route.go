package routing

// UserRouteRules is an immutable, comparable snapshot of explicitly declared
// userRoute values. Destination-dependent conditions are still evaluated by Router.
type UserRouteRules interface {
	ForUser(inboundTag, email string) []uint16
}

// UserRouteProvider is optional; it does not change the stable Router interface.
type UserRouteProvider interface {
	UserRouteRules() UserRouteRules
}
