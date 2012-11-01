package hacking

class Organization {

	String name

	static constraints = {
		name unique: true, blank: false
	}
}
