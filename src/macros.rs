/// Macro which implements the `TryFrom` trait for the given enum and type.
macro_rules! impl_enum_try_from {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }, $type:ty) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl TryFrom<$type> for $name {
            type Error = ();

            fn try_from(v: $type) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as $type => Ok($name::$vname),)*
                    _ => Err(()),
                }
            }
        }
    }
}

/// Macro which implements the `TryFrom` trait for the given enum and type, with
/// conversion of the input value from big endian.
macro_rules! impl_enum_try_from_be {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }, $type:ty) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl TryFrom<$type> for $name {
            type Error = ();

            fn try_from(v: $type) -> Result<Self, Self::Error> {
                let v = <$type>::from_be(v);
                match v {
                    $(x if x == $name::$vname as $type => Ok($name::$vname),)*
                    _ => Err(()),
                }
            }
        }
    }
}

pub(crate) use impl_enum_try_from;
pub(crate) use impl_enum_try_from_be;
