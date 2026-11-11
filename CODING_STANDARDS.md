# Coding Standards

- All codes must  follow the SOLID principle:
  Note: In Rust, read "class" as type, module, or trait.
  - Single responsibility principle (SRP): A class should have only one reason to change, meaning it should only have one job or responsibility.
      Example: Separate user database saving logic from user email notification logic.
  - Open/Closed Principle (OCP): Software entities should be open for extension, but closed for modification.
      Example: Add a new report format (like XML) by writing a new class instead of editing the existing report generator code.
      Note: Applies to extension points meant to grow (Generators, diagnostic renderers, Capabilities). IR enums such as `TypeDef` are deliberately closed so a new variant breaks every exhaustive `match`.
  - Liskov Substitution Principle (LSP): Objects of a superclass should be replaceable with objects of its subclasses without breaking the application.
      Example: A child class should not throw unexpected errors or change the core behavior expected from the parent class.
  - Interface Segregation Principle (ISP): No client should be forced to depend on methods it does not use; split large interfaces into smaller, specific ones.
      Example: Instead of a general Worker interface with work() and eat() methods, use separate Workable and Eatable interfaces.
  - Dependency Inversion Principle (DIP): High-level modules should not depend on low-level modules; both should depend on abstractions.
     Example:  A class should rely on a general Database or Tire interface rather than a hardcoded SQL class or specific tire brand
     Note: Introduce a trait only when two implementations exist today or at an OS boundary tests must fake; otherwise stay concrete (YAGNI). Pure data-in, data-out stages already satisfy this.
- Additional principles must be followed by codes:
  - DRY (Don't Repeat Yourself): Every piece of knowledge or logic must have a single, unambiguous, authoritative representation within a system.
      Example: Extract duplicate validation logic into a shared helper function instead of copying it across multiple form handlers.
  - KISS (Keep It Simple, Stupid): Systems work best when kept simple rather than over-engineered with unnecessary complexity.
      Example: Use a straightforward `if-else` statement for a few conditions rather than setting up a complex state machine pattern prematurely.
  - YAGNI (You Aren't Gonna Need It): Implement features only when actually needed, rather than in anticipation of future requirements.
      Example: Build a database interface for PostgreSQL only, without abstracting it to support multiple database engines until required.
  - Encapsulate What Varies: Identify parts of the application that frequently change and isolate them from stable parts.
      Example: Wrap third-party payment gateway APIs behind a wrapper class so changing providers does not affect the rest of the application.
  - Composition Over Inheritance: Favor combining simple objects to achieve complex behavior over deep class inheritance hierarchies.
      Example: Give a `Car` class an `Engine` object parameter rather than having `Car` inherit from an `Engine` base class.
  - Law of Demeter (Principle of Least Knowledge): An object should only interact with its immediate dependencies and avoid reaching through nested properties.
      Example: Call `customer.getCity()` directly instead of calling `customer.getAddress().getCity()`.
      Note: Applies to types with behavior, not plain immutable data; reading nested IR fields directly is fine, and forwarding getters are not wanted.
  - Program to an Interface, Not an Implementation: Depend on abstract types or interfaces rather than specific concrete classes.
      Example: Define a dependency as a `Logger` interface instead of a concrete `ConsoleLogger` class.
      Note: Same limit as DIP: a trait needs two real implementations or a test-faked OS boundary.
  - Principle of Least Surprise: Code should behave predictably and conform to standard conventions to avoid astonishing the developer.
      Example: Ensure a method named `getUser()` only retrieves data and does not silently mutate database records.

- Query path: no heap allocation per Query. Exception: a TCP Response buffer may grow once, on first use of its per-connection slot, up to the 65,535-octet Message limit; UDP buffers never grow.
